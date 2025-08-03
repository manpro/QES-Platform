import React, { useState } from 'react';
import {
  Paper,
  Typography,
  TextField,
  Button,
  Box,
  Alert,
  Card,
  CardContent,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider
} from '@mui/material';
import {
  Search,
  Verified,
  Error,
  Warning,
  Info,
  Person,
  CalendarToday,
  Security
} from '@mui/icons-material';

const SignatureStatus = () => {
  const [signatureId, setSignatureId] = useState('');
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // Real signature verification - no more mock data

  const verifySignature = async () => {
    if (!signatureId.trim()) return;
    
    setLoading(true);
    
    try {
      // Real API call to verify signature
      const response = await fetch(`http://localhost:8000/api/v1/signatures/${signatureId}/verify`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          // Add auth header if user is logged in
          ...(localStorage.getItem('auth_token') ? {
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
          } : {})
        }
      });

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Signatur hittades inte');
        } else if (response.status === 401) {
          throw new Error('Du måste logga in för att verifiera signaturer');
        }
        throw new Error(`Verifiering misslyckades: ${response.status}`);
      }

      const verificationData = await response.json();
      setVerificationResult(verificationData);

    } catch (err) {
      // Show error as verification result for better UX
      setVerificationResult({
        status: 'error',
        error: err.message,
        id: signatureId
      });
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'valid': return <Verified color="success" />;
      case 'invalid': return <Error color="error" />;
      case 'warning': return <Warning color="warning" />;
      default: return <Info color="info" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'valid': return 'success';
      case 'invalid': return 'error';
      case 'warning': return 'warning';
      default: return 'info';
    }
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Verifiera Signaturer
      </Typography>
      
      <Box sx={{ mb: 4 }}>
        <TextField
          fullWidth
          label="Signatur-ID eller dokument hash"
          value={signatureId}
          onChange={(e) => setSignatureId(e.target.value)}
          placeholder="Ange signatur-ID, t.ex. sig_12345"
          sx={{ mb: 2 }}
        />
        <Button
          variant="contained"
          startIcon={<Search />}
          onClick={verifySignature}
          disabled={loading || !signatureId.trim()}
          size="large"
        >
          {loading ? 'Verifierar...' : 'Verifiera Signatur'}
        </Button>
      </Box>

              {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {error}
          </Alert>
        )}

        {verificationResult && (
        <Box>
          <Alert 
            severity={getStatusColor(verificationResult.status)} 
            sx={{ mb: 3 }}
            icon={getStatusIcon(verificationResult.status)}
          >
            <Typography variant="h6">
              Signatur är {verificationResult.status === 'valid' ? 'giltig' : 'ogiltig'}
            </Typography>
            <Typography>
              Dokumentet har en gyltig kvalificerad elektronisk signatur enligt eIDAS.
            </Typography>
          </Alert>

          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Grundläggande information
              </Typography>
              <List>
                <ListItem>
                  <ListItemIcon><Person /></ListItemIcon>
                  <ListItemText 
                    primary="Signerare" 
                    secondary={`${verificationResult.signer.name} (${verificationResult.signer.email})`}
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CalendarToday /></ListItemIcon>
                  <ListItemText 
                    primary="Signerad" 
                    secondary={new Date(verificationResult.signedAt).toLocaleString('sv-SE')}
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><Security /></ListItemIcon>
                  <ListItemText 
                    primary="Provider" 
                    secondary={verificationResult.provider}
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>

          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Tekniska kontroller
              </Typography>
              <List>
                {Object.entries(verificationResult.checks).map(([check, status]) => (
                  <ListItem key={check}>
                    <ListItemIcon>
                      {getStatusIcon(status)}
                    </ListItemIcon>
                    <ListItemText 
                      primary={check.charAt(0).toUpperCase() + check.slice(1)} 
                      secondary={status}
                    />
                    <Chip 
                      label={status} 
                      color={getStatusColor(status)} 
                      size="small" 
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Regelefterlevnad
              </Typography>
              <Box display="flex" gap={1} flexWrap="wrap">
                <Chip 
                  label={`eIDAS: ${verificationResult.compliance.eidas}`} 
                  color="primary" 
                />
                <Chip 
                  label={`ETSI: ${verificationResult.compliance.etsi}`} 
                  color="secondary" 
                />
                <Chip 
                  label={`LTV: ${verificationResult.compliance.ltv}`} 
                  color="success" 
                />
                <Chip 
                  label={`Format: ${verificationResult.format}`} 
                  color="info" 
                />
              </Box>
            </CardContent>
          </Card>
        </Box>
      )}

      {!verificationResult && !loading && (
        <Alert severity="info">
          Ange ett signatur-ID eller dokument hash för att verifiera en elektronisk signatur.
        </Alert>
      )}
    </Paper>
  );
};

export default SignatureStatus;