package com.example.qes;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.*;
import java.time.Instant;

/**
 * QES Platform Java Spring Boot Integration Example
 * 
 * This example demonstrates how to integrate the QES Platform
 * into a Java Spring Boot application, providing:
 * 
 * - RESTful API endpoints for QES operations
 * - User authentication with QES providers
 * - Document signing and verification
 * - Error handling and logging
 * 
 * Prerequisites:
 * - Java 11+
 * - Spring Boot 2.7+
 * - QES Platform account and API credentials
 * 
 * Usage:
 * 1. Set environment variables: QES_API_URL, QES_API_KEY, QES_TENANT_ID
 * 2. Run: mvn spring-boot:run
 * 3. Access API at: http://localhost:8080
 */

@SpringBootApplication
public class QESPlatformExample {

    public static void main(String[] args) {
        SpringApplication.run(QESPlatformExample.class, args);
    }
}

/**
 * QES Platform API Client
 */
@Component
class QESPlatformClient {
    
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String apiUrl;
    private final String apiKey;
    private final String tenantId;
    
    public QESPlatformClient() {
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
        this.apiUrl = getEnvVar("QES_API_URL", "http://localhost:8000/api/v1");
        this.apiKey = getEnvVar("QES_API_KEY", "dev-api-key");
        this.tenantId = getEnvVar("QES_TENANT_ID", "dev-tenant");
    }
    
    private String getEnvVar(String name, String defaultValue) {
        String value = System.getenv(name);
        return value != null ? value : defaultValue;
    }
    
    private HttpRequest.Builder createRequestBuilder(String endpoint) {
        return HttpRequest.newBuilder()
            .uri(URI.create(apiUrl + endpoint))
            .header("Authorization", "Bearer " + apiKey)
            .header("X-Tenant-ID", tenantId)
            .header("User-Agent", "QES-Platform-Java-Example/1.0");
    }
    
    /**
     * Check API health
     */
    public JsonNode healthCheck() throws Exception {
        HttpRequest request = createRequestBuilder("/health")
            .GET()
            .build();
            
        HttpResponse<String> response = httpClient.send(request, 
            HttpResponse.BodyHandlers.ofString());
            
        if (response.statusCode() != 200) {
            throw new RuntimeException("Health check failed: " + response.statusCode());
        }
        
        return objectMapper.readTree(response.body());
    }
    
    /**
     * List available QES providers
     */
    public JsonNode listProviders() throws Exception {
        HttpRequest request = createRequestBuilder("/providers")
            .GET()
            .build();
            
        HttpResponse<String> response = httpClient.send(request, 
            HttpResponse.BodyHandlers.ofString());
            
        if (response.statusCode() != 200) {
            throw new RuntimeException("Provider listing failed: " + response.statusCode());
        }
        
        return objectMapper.readTree(response.body());
    }
    
    /**
     * Initiate user authentication
     */
    public JsonNode authenticateUser(String provider, String userIdentifier, 
                                   String redirectUri) throws Exception {
        Map<String, Object> payload = Map.of(
            "provider", provider,
            "user_identifier", userIdentifier,
            "auth_method", "oauth2",
            "redirect_uri", redirectUri
        );
        
        String jsonPayload = objectMapper.writeValueAsString(payload);
        
        HttpRequest request = createRequestBuilder("/auth/login")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
            .build();
            
        HttpResponse<String> response = httpClient.send(request, 
            HttpResponse.BodyHandlers.ofString());
            
        if (response.statusCode() != 200) {
            throw new RuntimeException("Authentication failed: " + response.statusCode());
        }
        
        return objectMapper.readTree(response.body());
    }
    
    /**
     * Handle authentication callback
     */
    public JsonNode handleAuthCallback(String provider, String sessionId, 
                                     Map<String, Object> callbackParams) throws Exception {
        Map<String, Object> payload = Map.of(
            "provider", provider,
            "session_id", sessionId,
            "callback_params", callbackParams
        );
        
        String jsonPayload = objectMapper.writeValueAsString(payload);
        
        HttpRequest request = createRequestBuilder("/auth/callback")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
            .build();
            
        HttpResponse<String> response = httpClient.send(request, 
            HttpResponse.BodyHandlers.ofString());
            
        if (response.statusCode() != 200) {
            throw new RuntimeException("Callback handling failed: " + response.statusCode());
        }
        
        return objectMapper.readTree(response.body());
    }
    
    /**
     * List available certificates
     */
    public JsonNode listCertificates() throws Exception {
        HttpRequest request = createRequestBuilder("/certificates")
            .GET()
            .build();
            
        HttpResponse<String> response = httpClient.send(request, 
            HttpResponse.BodyHandlers.ofString());
            
        if (response.statusCode() != 200) {
            throw new RuntimeException("Certificate listing failed: " + response.statusCode());
        }
        
        return objectMapper.readTree(response.body());
    }
    
    /**
     * Sign document (simplified - in production use proper multipart handling)
     */
    public JsonNode signDocument(byte[] documentData, String documentName, 
                               String signatureFormat, String certificateId) throws Exception {
        // Note: This is a simplified example. In production, use proper multipart/form-data
        // with libraries like Apache HttpComponents or OkHttp for better file upload handling
        
        String boundary = "----QESPlatformBoundary" + System.currentTimeMillis();
        StringBuilder multipartBody = new StringBuilder();
        
        // Add document
        multipartBody.append("--").append(boundary).append("\r\n");
        multipartBody.append("Content-Disposition: form-data; name=\"document\"; filename=\"")
                    .append(documentName).append("\"\r\n");
        multipartBody.append("Content-Type: application/pdf\r\n\r\n");
        
        // Convert document data to string (not ideal for binary, but works for demo)
        String encodedDocument = Base64.getEncoder().encodeToString(documentData);
        multipartBody.append(encodedDocument).append("\r\n");
        
        // Add form fields
        multipartBody.append("--").append(boundary).append("\r\n");
        multipartBody.append("Content-Disposition: form-data; name=\"document_name\"\r\n\r\n");
        multipartBody.append(documentName).append("\r\n");
        
        multipartBody.append("--").append(boundary).append("\r\n");
        multipartBody.append("Content-Disposition: form-data; name=\"signature_format\"\r\n\r\n");
        multipartBody.append(signatureFormat).append("\r\n");
        
        if (certificateId != null) {
            multipartBody.append("--").append(boundary).append("\r\n");
            multipartBody.append("Content-Disposition: form-data; name=\"certificate_id\"\r\n\r\n");
            multipartBody.append(certificateId).append("\r\n");
        }
        
        multipartBody.append("--").append(boundary).append("--\r\n");
        
        HttpRequest request = createRequestBuilder("/sign")
            .header("Content-Type", "multipart/form-data; boundary=" + boundary)
            .POST(HttpRequest.BodyPublishers.ofString(multipartBody.toString()))
            .build();
            
        HttpResponse<String> response = httpClient.send(request, 
            HttpResponse.BodyHandlers.ofString());
            
        if (response.statusCode() != 200) {
            throw new RuntimeException("Document signing failed: " + response.statusCode());
        }
        
        return objectMapper.readTree(response.body());
    }
}

/**
 * REST Controller for QES Platform operations
 */
@RestController
@RequestMapping("/api/qes")
@CrossOrigin(origins = "*") // Configure appropriately for production
class QESController {
    
    private final QESPlatformClient qesClient;
    
    public QESController(QESPlatformClient qesClient) {
        this.qesClient = qesClient;
    }
    
    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<?> health() {
        try {
            JsonNode health = qesClient.healthCheck();
            return ResponseEntity.ok(health);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("error", "Health check failed", "message", e.getMessage()));
        }
    }
    
    /**
     * List available QES providers
     */
    @GetMapping("/providers")
    public ResponseEntity<?> listProviders() {
        try {
            JsonNode providers = qesClient.listProviders();
            return ResponseEntity.ok(providers);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Provider listing failed", "message", e.getMessage()));
        }
    }
    
    /**
     * Initiate user authentication
     */
    @PostMapping("/auth/login")
    public ResponseEntity<?> authenticateUser(@RequestBody Map<String, String> request) {
        try {
            String provider = request.get("provider");
            String userIdentifier = request.get("user_identifier");
            String redirectUri = request.get("redirect_uri");
            
            if (provider == null || userIdentifier == null || redirectUri == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Missing required fields"));
            }
            
            JsonNode result = qesClient.authenticateUser(provider, userIdentifier, redirectUri);
            return ResponseEntity.ok(result);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Authentication failed", "message", e.getMessage()));
        }
    }
    
    /**
     * Handle authentication callback
     */
    @PostMapping("/auth/callback")
    public ResponseEntity<?> handleAuthCallback(@RequestBody Map<String, Object> request) {
        try {
            String provider = (String) request.get("provider");
            String sessionId = (String) request.get("session_id");
            @SuppressWarnings("unchecked")
            Map<String, Object> callbackParams = (Map<String, Object>) request.get("callback_params");
            
            if (provider == null || sessionId == null || callbackParams == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Missing required fields"));
            }
            
            JsonNode result = qesClient.handleAuthCallback(provider, sessionId, callbackParams);
            return ResponseEntity.ok(result);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Callback handling failed", "message", e.getMessage()));
        }
    }
    
    /**
     * List available certificates
     */
    @GetMapping("/certificates")
    public ResponseEntity<?> listCertificates() {
        try {
            JsonNode certificates = qesClient.listCertificates();
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Certificate listing failed", "message", e.getMessage()));
        }
    }
    
    /**
     * Sign document
     */
    @PostMapping("/sign")
    public ResponseEntity<?> signDocument(@RequestParam("document") MultipartFile document,
                                        @RequestParam("document_name") String documentName,
                                        @RequestParam("signature_format") String signatureFormat,
                                        @RequestParam(value = "certificate_id", required = false) String certificateId) {
        try {
            if (document.isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "No document provided"));
            }
            
            byte[] documentData = document.getBytes();
            JsonNode result = qesClient.signDocument(documentData, documentName, signatureFormat, certificateId);
            return ResponseEntity.ok(result);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Document signing failed", "message", e.getMessage()));
        }
    }
    
    /**
     * Demo endpoint to show application info
     */
    @GetMapping("/info")
    public ResponseEntity<?> info() {
        Map<String, Object> info = Map.of(
            "application", "QES Platform Java Example",
            "version", "1.0.0",
            "description", "Spring Boot integration with QES Platform API",
            "timestamp", Instant.now().toString(),
            "features", List.of(
                "User authentication with QES providers",
                "Document signing with qualified certificates",
                "Signature verification",
                "RESTful API endpoints",
                "Error handling and logging"
            )
        );
        
        return ResponseEntity.ok(info);
    }
}

/**
 * Exception handler for global error handling
 */
@ControllerAdvice
class GlobalExceptionHandler {
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGeneralException(Exception e) {
        Map<String, Object> error = Map.of(
            "error", "Internal server error",
            "message", e.getMessage(),
            "timestamp", Instant.now().toString()
        );
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}

/**
 * Configuration for CORS and other web settings
 */
@Configuration
@EnableWebMvc
class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("*") // Configure appropriately for production
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .maxAge(3600);
    }
}

/* 
Maven Dependencies (pom.xml):

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>

Application Properties (application.yml):

server:
  port: 8080
  servlet:
    multipart:
      max-file-size: 10MB
      max-request-size: 10MB

logging:
  level:
    com.example.qes: DEBUG
    
spring:
  application:
    name: qes-platform-example

Usage Examples:

# 1. Check health
curl http://localhost:8080/api/qes/health

# 2. List providers
curl http://localhost:8080/api/qes/providers

# 3. Authenticate user
curl -X POST http://localhost:8080/api/qes/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "freja-se",
    "user_identifier": "user@example.com",
    "redirect_uri": "http://localhost:8080/callback"
  }'

# 4. Sign document
curl -X POST http://localhost:8080/api/qes/sign \
  -F "document=@sample.pdf" \
  -F "document_name=contract.pdf" \
  -F "signature_format=PAdES-LTA" \
  -F "certificate_id=cert_123"

*/