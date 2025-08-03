import React from 'react';
import {
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Box,
  Avatar,
  List,
  ListItem,
  ListItemText,
  ListItemAvatar,
  Button
} from '@mui/material';
import {
  Security,
  CheckCircle,
  Public,
  Speed,
  VerifiedUser
} from '@mui/icons-material';

const ProvidersList = () => {
  const providers = [
    {
      id: 'freja-se',
      name: 'Freja eID QES',
      country: 'Sverige',
      flag: '🇸🇪',
      status: 'active',
      description: 'Kvalificerade elektroniska signaturer via Freja eID',
      features: ['OAuth2 Authentication', 'Mobile Biometrics', 'SCIM User Lookup'],
      compliance: ['eIDAS QES', 'ETSI EN 319 142-1', 'Swedish BankID'],
      setupTime: '~2 min'
    },
    {
      id: 'dtrust-de',
      name: 'D-Trust',
      country: 'Tyskland',
      flag: '🇩🇪',
      status: 'active',
      description: 'Tyska kvalificerade certifikat via D-Trust',
      features: ['eIDAS Node Integration', 'Remote Signing API', 'Strong Authentication'],
      compliance: ['eIDAS QES', 'ETSI EN 319 142-1', 'German Digital Identity'],
      setupTime: '~5 min'
    },
    {
      id: 'fnmt-es',
      name: 'FNMT QES',
      country: 'Spanien',
      flag: '🇪🇸',
      status: 'active',
      description: 'Spanska statliga kvalificerade certifikat',
      features: ['DNI/NIF Validation', 'Government Integration', 'ENI Compliance'],
      compliance: ['eIDAS QES', 'ENI Compliance', 'Spanish Regulations'],
      setupTime: '~3 min'
    },
    {
      id: 'itsme-be',
      name: 'itsme',
      country: 'Belgien/Nederländerna',
      flag: '🇧🇪🇳🇱',
      status: 'active',
      description: 'App-baserad autentisering och kvalificerade signaturer',
      features: ['Mobile App Auth', 'Biometric Verification', 'Cross-Border'],
      compliance: ['eIDAS QES', 'LoA Substantial', 'Mobile Security'],
      setupTime: '~4 min'
    },
    {
      id: 'certinomis-fr',
      name: 'Certinomis',
      country: 'Frankrike',
      flag: '🇫🇷',
      status: 'active',
      description: 'Franska kvalificerade certifikat via Certinomis',
      features: ['FranceConnect Integration', 'Remote Signing', 'High LoA'],
      compliance: ['eIDAS QES', 'ETSI Standards', 'French Regulations'],
      setupTime: '~3 min'
    },
    {
      id: 'camerfirma-es',
      name: 'Camerfirma',
      country: 'Spanien',
      flag: '🇪🇸',
      status: 'available',
      description: 'Kommersiella kvalificerade certifikat från Camerfirma',
      features: ['Mobile Signatures', 'DNI/NIE Verification', 'Business Certificates'],
      compliance: ['eIDAS QES', 'ENI Compliance', 'Commercial Grade'],
      setupTime: '~5 min'
    }
  ];

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'success';
      case 'available': return 'primary';
      case 'maintenance': return 'warning';
      default: return 'default';
    }
  };

  const getStatusLabel = (status) => {
    switch (status) {
      case 'active': return 'Aktiv';
      case 'available': return 'Tillgänglig';
      case 'maintenance': return 'Underhåll';
      default: return 'Okänd';
    }
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        QES-leverantörer
      </Typography>
      
      <Typography variant="body1" color="textSecondary" sx={{ mb: 3 }}>
        Tillgängliga leverantörer av kvalificerade elektroniska signaturer (QES) 
        enligt eIDAS-förordningen. Alla leverantörer stödjer fjärrsignering och 
        stark autentisering.
      </Typography>

      <Grid container spacing={3}>
        {providers.map((provider) => (
          <Grid item xs={12} md={6} lg={4} key={provider.id}>
            <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <CardContent sx={{ flexGrow: 1 }}>
                <Box display="flex" alignItems="center" mb={2}>
                  <Avatar sx={{ mr: 2, fontSize: '1.5rem' }}>
                    {provider.flag}
                  </Avatar>
                  <Box>
                    <Typography variant="h6" component="h3">
                      {provider.name}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      {provider.country}
                    </Typography>
                  </Box>
                  <Box ml="auto">
                    <Chip 
                      label={getStatusLabel(provider.status)} 
                      color={getStatusColor(provider.status)}
                      size="small"
                    />
                  </Box>
                </Box>

                <Typography variant="body2" sx={{ mb: 2 }}>
                  {provider.description}
                </Typography>

                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Funktioner:
                </Typography>
                <List dense sx={{ mb: 2 }}>
                  {provider.features.map((feature, index) => (
                    <ListItem key={index} sx={{ py: 0, px: 0 }}>
                      <ListItemAvatar sx={{ minWidth: 'auto', mr: 1 }}>
                        <CheckCircle color="success" sx={{ fontSize: 16 }} />
                      </ListItemAvatar>
                      <ListItemText 
                        primary={feature} 
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  ))}
                </List>

                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Regelefterlevnad:
                </Typography>
                <Box display="flex" gap={0.5} flexWrap="wrap" mb={2}>
                  {provider.compliance.map((item, index) => (
                    <Chip 
                      key={index}
                      label={item} 
                      size="small" 
                      variant="outlined"
                    />
                  ))}
                </Box>

                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box display="flex" alignItems="center">
                    <Speed sx={{ fontSize: 16, mr: 0.5, color: 'text.secondary' }} />
                    <Typography variant="body2" color="textSecondary">
                      Setup: {provider.setupTime}
                    </Typography>
                  </Box>
                  
                  <Button
                    size="small"
                    variant={provider.status === 'active' ? 'contained' : 'outlined'}
                    startIcon={<Security />}
                    disabled={provider.status === 'maintenance'}
                  >
                    {provider.status === 'active' ? 'Konfigurera' : 'Aktivera'}
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Box mt={4}>
        <Paper sx={{ p: 2, backgroundColor: '#f5f5f5' }}>
          <Typography variant="h6" gutterBottom display="flex" alignItems="center">
            <VerifiedUser sx={{ mr: 1 }} />
            Om eIDAS QES
          </Typography>
          <Typography variant="body2">
            Alla leverantörer följer eIDAS-förordningen (Electronic IDentification, 
            Authentication and trust Services) och tillhandahåller kvalificerade 
            elektroniska signaturer (QES) som har samma juridiska status som 
            handskrivna signaturer inom EU.
          </Typography>
        </Paper>
      </Box>
    </Paper>
  );
};

export default ProvidersList;