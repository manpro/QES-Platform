"""
eIDAS Node Client

Handles SAML-based authentication through German eIDAS nodes
for identity verification and attribute retrieval.
"""

import base64
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from urllib.parse import urlencode, parse_qs, urlparse
import hashlib
import httpx


class eIDASError(Exception):
    """eIDAS-related errors"""
    def __init__(self, message: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.error_code = error_code


class eIDASClient:
    """
    Client for German eIDAS authentication nodes.
    
    Implements SAML 2.0 protocols for cross-border
    authentication within the EU eIDAS framework.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.node_url = config["node_url"]
        self.sp_entity_id = config["sp_entity_id"]
        self.sp_return_url = config["sp_return_url"]
        
        # SAML configuration
        self.sp_cert_file = config.get("sp_cert_file")
        self.sp_key_file = config.get("sp_key_file")
        self.idp_cert_file = config.get("idp_cert_file")
        
        # eIDAS specific settings
        self.country_code = config.get("country_code", "DE")
        self.citizen_country = config.get("citizen_country", "DE")
        self.sp_type = config.get("sp_type", "public")
        
        # Timeout settings
        self.timeout = config.get("timeout", 30)
    
    def create_authentication_request(self, 
                                    requested_attributes: Optional[List[str]] = None,
                                    loa_level: str = "substantial") -> Dict[str, Any]:
        """
        Create SAML authentication request for eIDAS.
        
        Args:
            requested_attributes: List of eIDAS attributes to request
            loa_level: Level of Assurance (notified, substantial, high)
            
        Returns:
            Dictionary with SAML request and metadata
        """
        
        if not requested_attributes:
            requested_attributes = [
                "PersonIdentifier",
                "FamilyName",
                "FirstName", 
                "DateOfBirth"
            ]
        
        request_id = self._generate_request_id()
        issue_instant = datetime.now(timezone.utc).isoformat()
        
        # Create SAML AuthnRequest
        authn_request = self._build_saml_authn_request(
            request_id=request_id,
            issue_instant=issue_instant,
            destination=self.node_url,
            issuer=self.sp_entity_id,
            loa_level=loa_level,
            requested_attributes=requested_attributes
        )
        
        # Encode SAML request
        saml_request = base64.b64encode(authn_request.encode('utf-8')).decode('utf-8')
        
        # Create relay state for tracking
        relay_state = self._generate_relay_state(request_id)
        
        return {
            "request_id": request_id,
            "saml_request": saml_request,
            "relay_state": relay_state,
            "destination": self.node_url,
            "loa_level": loa_level,
            "requested_attributes": requested_attributes
        }
    
    def build_redirect_url(self, saml_request: str, relay_state: str) -> str:
        """
        Build redirect URL for eIDAS authentication.
        
        Args:
            saml_request: Base64 encoded SAML request
            relay_state: Relay state parameter
            
        Returns:
            Complete redirect URL
        """
        
        params = {
            "SAMLRequest": saml_request,
            "RelayState": relay_state
        }
        
        return f"{self.node_url}?{urlencode(params)}"
    
    async def send_authentication_request(self, saml_request: str,
                                        relay_state: str) -> str:
        """
        Send authentication request to eIDAS node.
        
        Args:
            saml_request: Base64 encoded SAML request
            relay_state: Relay state parameter
            
        Returns:
            Redirect URL for user authentication
        """
        
        try:
            # Prepare form data for POST binding
            form_data = {
                "SAMLRequest": saml_request,
                "RelayState": relay_state
            }
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.node_url,
                    data=form_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                if response.status_code in [302, 303]:
                    # Follow redirect
                    redirect_url = response.headers.get("Location")
                    if redirect_url:
                        return redirect_url
                
                if response.status_code != 200:
                    raise eIDASError(
                        f"eIDAS node error: {response.status_code} - {response.text}",
                        error_code="EIDAS_NODE_ERROR"
                    )
                
                # Extract redirect URL from HTML if no redirect header
                html_content = response.text
                redirect_url = self._extract_redirect_from_html(html_content)
                
                if not redirect_url:
                    raise eIDASError(
                        "No redirect URL found in eIDAS response",
                        error_code="EIDAS_NO_REDIRECT"
                    )
                
                return redirect_url
                
        except httpx.RequestError as e:
            raise eIDASError(f"Network error contacting eIDAS node: {str(e)}")
    
    def parse_saml_response(self, saml_response: str,
                          relay_state: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse and validate SAML response from eIDAS.
        
        Args:
            saml_response: Base64 encoded SAML response
            relay_state: Relay state from original request
            
        Returns:
            Parsed authentication result with attributes
        """
        
        try:
            # Decode SAML response
            saml_xml = base64.b64decode(saml_response).decode('utf-8')
            
            # Parse XML
            root = ET.fromstring(saml_xml)
            
            # Define namespaces
            ns = {
                'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
                'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'
            }
            
            # Extract status
            status_element = root.find('.//saml2p:Status/saml2p:StatusCode', ns)
            status_code = status_element.get('Value') if status_element is not None else None
            
            is_success = status_code and 'Success' in status_code
            
            if not is_success:
                status_message = self._extract_status_message(root, ns)
                return {
                    "success": False,
                    "error": status_message or "Authentication failed",
                    "status_code": status_code
                }
            
            # Extract assertion
            assertion = root.find('.//saml2:Assertion', ns)
            if assertion is None:
                raise eIDASError("No assertion found in SAML response")
            
            # Extract attributes
            attributes = self._extract_attributes(assertion, ns)
            
            # Extract authentication context
            authn_context = self._extract_authn_context(assertion, ns)
            
            # Extract subject
            subject_data = self._extract_subject(assertion, ns)
            
            return {
                "success": True,
                "attributes": attributes,
                "authentication_context": authn_context,
                "subject": subject_data,
                "relay_state": relay_state,
                "response_id": root.get('ID'),
                "assertion_id": assertion.get('ID'),
                "issue_instant": root.get('IssueInstant')
            }
            
        except ET.ParseError as e:
            raise eIDASError(f"Invalid SAML XML: {str(e)}", error_code="INVALID_SAML")
        except Exception as e:
            raise eIDASError(f"Error parsing SAML response: {str(e)}")
    
    def validate_saml_response(self, parsed_response: Dict[str, Any]) -> bool:
        """
        Validate SAML response authenticity and integrity.
        
        Args:
            parsed_response: Parsed SAML response
            
        Returns:
            True if response is valid
        """
        
        # In production, implement:
        # 1. Signature validation using IdP certificate
        # 2. Timestamp validation (NotBefore/NotOnOrAfter)
        # 3. Audience restriction validation
        # 4. Response destination validation
        # 5. Assertion conditions validation
        
        # Placeholder validation
        required_fields = ["success", "attributes"]
        for field in required_fields:
            if field not in parsed_response:
                return False
        
        # Check if response indicates success
        if not parsed_response.get("success", False):
            return False
        
        # Validate required attributes are present
        attributes = parsed_response.get("attributes", {})
        required_attributes = ["PersonIdentifier"]
        
        for attr in required_attributes:
            if attr not in attributes:
                return False
        
        return True
    
    def _build_saml_authn_request(self, request_id: str, issue_instant: str,
                                destination: str, issuer: str, loa_level: str,
                                requested_attributes: List[str]) -> str:
        """Build SAML authentication request XML."""
        
        # Map LoA level to SAML AuthnContextClassRef
        loa_mapping = {
            "low": "http://eidas.europa.eu/LoA/low",
            "substantial": "http://eidas.europa.eu/LoA/substantial", 
            "high": "http://eidas.europa.eu/LoA/high"
        }
        
        loa_uri = loa_mapping.get(loa_level, loa_mapping["substantial"])
        
        # Build attribute list
        attribute_list = ""
        for attr in requested_attributes:
            attribute_list += f'''
                <eidas:RequestedAttribute Name="{attr}" 
                    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" 
                    isRequired="true"/>'''
        
        # Build complete SAML request
        saml_request = f'''<?xml version="1.0" encoding="UTF-8"?>
<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                     xmlns:eidas="http://eidas.europa.eu/saml-extensions"
                     ID="{request_id}"
                     Version="2.0"
                     IssueInstant="{issue_instant}"
                     Destination="{destination}"
                     ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                     AssertionConsumerServiceURL="{self.sp_return_url}">
    <saml2:Issuer>{issuer}</saml2:Issuer>
    <saml2p:Extensions>
        <eidas:SPType>{self.sp_type}</eidas:SPType>
        <eidas:RequesterID>{issuer}</eidas:RequesterID>
    </saml2p:Extensions>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" 
                         AllowCreate="true"/>
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef>{loa_uri}</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
    <saml2p:AttributeConsumingService Index="0">
        <saml2p:ServiceName xml:lang="en">D-Trust QES Service</saml2p:ServiceName>
        {attribute_list}
    </saml2p:AttributeConsumingService>
</saml2p:AuthnRequest>'''
        
        return saml_request
    
    def _extract_attributes(self, assertion: ET.Element, ns: Dict[str, str]) -> Dict[str, str]:
        """Extract eIDAS attributes from SAML assertion."""
        
        attributes = {}
        
        # Find attribute statements
        attr_statements = assertion.findall('.//saml2:AttributeStatement', ns)
        
        for attr_stmt in attr_statements:
            for attr in attr_stmt.findall('saml2:Attribute', ns):
                attr_name = attr.get('Name', '')
                
                # Extract attribute values
                attr_values = []
                for attr_value in attr.findall('saml2:AttributeValue', ns):
                    if attr_value.text:
                        attr_values.append(attr_value.text)
                
                if attr_values:
                    # Use friendly name or extract from URI
                    friendly_name = attr.get('FriendlyName')
                    if friendly_name:
                        attributes[friendly_name] = attr_values[0]
                    else:
                        # Extract attribute name from URI
                        attr_key = attr_name.split('/')[-1] if '/' in attr_name else attr_name
                        attributes[attr_key] = attr_values[0]
        
        return attributes
    
    def _extract_authn_context(self, assertion: ET.Element, ns: Dict[str, str]) -> Dict[str, str]:
        """Extract authentication context from assertion."""
        
        authn_stmt = assertion.find('.//saml2:AuthnStatement', ns)
        if authn_stmt is None:
            return {}
        
        authn_context = authn_stmt.find('saml2:AuthnContext', ns)
        if authn_context is None:
            return {}
        
        context_class_ref = authn_context.find('saml2:AuthnContextClassRef', ns)
        
        return {
            "authn_instant": authn_stmt.get('AuthnInstant', ''),
            "authn_context_class_ref": context_class_ref.text if context_class_ref is not None else '',
            "session_index": authn_stmt.get('SessionIndex', '')
        }
    
    def _extract_subject(self, assertion: ET.Element, ns: Dict[str, str]) -> Dict[str, str]:
        """Extract subject information from assertion."""
        
        subject = assertion.find('saml2:Subject', ns)
        if subject is None:
            return {}
        
        name_id = subject.find('saml2:NameID', ns)
        
        return {
            "name_id": name_id.text if name_id is not None else '',
            "name_id_format": name_id.get('Format', '') if name_id is not None else ''
        }
    
    def _extract_status_message(self, root: ET.Element, ns: Dict[str, str]) -> Optional[str]:
        """Extract status message from SAML response."""
        
        status_msg = root.find('.//saml2p:Status/saml2p:StatusMessage', ns)
        return status_msg.text if status_msg is not None else None
    
    def _extract_redirect_from_html(self, html_content: str) -> Optional[str]:
        """Extract redirect URL from HTML response."""
        
        # Look for common redirect patterns in HTML
        patterns = [
            'window.location.href="',
            'window.location="',
            '<meta http-equiv="refresh" content="0;url=',
            'location.replace("'
        ]
        
        for pattern in patterns:
            start = html_content.find(pattern)
            if start != -1:
                start += len(pattern)
                end = html_content.find('"', start)
                if end != -1:
                    return html_content[start:end]
        
        return None
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        import uuid
        return f"_eidas_{uuid.uuid4().hex}"
    
    def _generate_relay_state(self, request_id: str) -> str:
        """Generate relay state for request tracking."""
        return base64.b64encode(
            f"{request_id}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).decode()
    
    def parse_relay_state(self, relay_state: str) -> Dict[str, str]:
        """Parse relay state to extract request information."""
        
        try:
            decoded = base64.b64decode(relay_state).decode()
            parts = decoded.split(':', 1)
            
            return {
                "request_id": parts[0] if len(parts) > 0 else '',
                "timestamp": parts[1] if len(parts) > 1 else ''
            }
        except Exception:
            return {"request_id": "", "timestamp": ""}