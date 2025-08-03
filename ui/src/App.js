import React, { useState, useEffect } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Paper,
  Grid,
  Card,
  CardContent,
  Button,
  Box,
  Chip,
  Alert,
  CircularProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider
} from '@mui/material';
import {
  CloudUpload,
  Security,
  Verified,
  AccountCircle,
  Dashboard,
  Description,
  CheckCircle,
  Error,
  Info
} from '@mui/icons-material';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import DocumentUploader from './components/DocumentUploader';
import SignatureStatus from './components/SignatureStatus';
import ProvidersList from './components/ProvidersList';
import DocumentManager from './components/DocumentManager';
import AuthManager from './components/AuthManager';
import { AuthProvider } from './contexts/AuthContext';

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

function App() {
  const [apiHealth, setApiHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    checkAPIHealth();
  }, []);

  const checkAPIHealth = async () => {
    try {
      const apiUrl = 'http://localhost:8000';
      const response = await fetch(`${apiUrl}/health`);
      const data = await response.json();
      setApiHealth(data);
    } catch (error) {
      console.error('Failed to check API health:', error);
    } finally {
      setLoading(false);
    }
  };

  const ServiceCard = ({ title, description, status, icon, onClick, disabled = false }) => (
    <Card 
      sx={{ 
        height: '100%', 
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.6 : 1,
        '&:hover': {
          boxShadow: disabled ? 1 : 4,
        }
      }}
      onClick={disabled ? undefined : onClick}
    >
      <CardContent>
        <Box display="flex" alignItems="center" mb={2}>
          {icon}
          <Typography variant="h6" component="h2" ml={2}>
            {title}
          </Typography>
        </Box>
        <Typography variant="body2" color="textSecondary" mb={2}>
          {description}
        </Typography>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Chip 
            label={status} 
            color={status === 'Available' ? 'success' : status === 'Ready' ? 'primary' : 'default'}
            size="small"
          />
        </Box>
      </CardContent>
    </Card>
  );

  const renderContent = () => {
    switch (activeTab) {
      case 'sign':
        return <DocumentUploader />;
      case 'verify':
        return <SignatureStatus />;
      case 'providers':
        return <ProvidersList />;
      case 'documents':
        return <DocumentManager />;
      default:
        return (
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Alert severity="info" sx={{ mb: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Välkommen till QES Platform
                </Typography>
                <Typography>
                  En komplett lösning för eIDAS-kompatibel kvalificerad elektronisk signering.
                  Välj en tjänst nedan för att komma igång.
                </Typography>
              </Alert>
            </Grid>

            <Grid item xs={12} md={4}>
              <ServiceCard
                title="Signera Dokument"
                description="Ladda upp och signera dokument med kvalificerade elektroniska signaturer"
                status="Ready"
                icon={<CloudUpload color="primary" />}
                onClick={() => setActiveTab('sign')}
              />
            </Grid>

            <Grid item xs={12} md={4}>
              <ServiceCard
                title="Verifiera Signaturer"
                description="Kontrollera och validera befintliga elektroniska signaturer"
                status="Ready"
                icon={<Verified color="primary" />}
                onClick={() => setActiveTab('verify')}
              />
            </Grid>

            <Grid item xs={12} md={4}>
              <ServiceCard
                title="QES-leverantörer"
                description="Hantera och konfigurera kvalificerade signaturleverantörer"
                status="Available"
                icon={<Security color="primary" />}
                onClick={() => setActiveTab('providers')}
              />
            </Grid>

            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom display="flex" alignItems="center">
                  <Dashboard sx={{ mr: 1 }} />
                  Systemstatus
                </Typography>
                <Divider sx={{ mb: 2 }} />
                
                {loading ? (
                  <Box display="flex" justifyContent="center" p={3}>
                    <CircularProgress />
                  </Box>
                ) : apiHealth ? (
                  <List>
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircle color="success" />
                      </ListItemIcon>
                      <ListItemText 
                        primary="API Service" 
                        secondary={`Version ${apiHealth.version} - ${apiHealth.status}`}
                      />
                    </ListItem>
                    {apiHealth.checks && Object.entries(apiHealth.checks).map(([service, status]) => (
                      <ListItem key={service}>
                        <ListItemIcon>
                          {status === 'ok' ? 
                            <CheckCircle color="success" /> : 
                            <Error color="error" />
                          }
                        </ListItemIcon>
                        <ListItemText 
                          primary={service.charAt(0).toUpperCase() + service.slice(1)} 
                          secondary={status}
                        />
                      </ListItem>
                    ))}
                  </List>
                ) : (
                  <Alert severity="error">
                    Kunde inte ansluta till API-service
                  </Alert>
                )}
              </Paper>
            </Grid>
          </Grid>
        );
    }
  };

  return (
    <AuthProvider>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box sx={{ flexGrow: 1, minHeight: '100vh', backgroundColor: '#f5f5f5' }}>
        <AppBar position="static">
          <Toolbar>
            <Security sx={{ mr: 2 }} />
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              QES Platform - eIDAS Digital Signing
            </Typography>
            <AuthManager />
          </Toolbar>
        </AppBar>

        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Box sx={{ mb: 3 }}>
            <Button
              variant={activeTab === 'overview' ? 'contained' : 'outlined'}
              onClick={() => setActiveTab('overview')}
              sx={{ mr: 1 }}
              startIcon={<Dashboard />}
            >
              Översikt
            </Button>
            <Button
              variant={activeTab === 'sign' ? 'contained' : 'outlined'}
              onClick={() => setActiveTab('sign')}
              sx={{ mr: 1 }}
              startIcon={<CloudUpload />}
            >
              Signera
            </Button>
            <Button
              variant={activeTab === 'verify' ? 'contained' : 'outlined'}
              onClick={() => setActiveTab('verify')}
              sx={{ mr: 1 }}
              startIcon={<Verified />}
            >
              Verifiera
            </Button>
            <Button
              variant={activeTab === 'providers' ? 'contained' : 'outlined'}
              onClick={() => setActiveTab('providers')}
              startIcon={<Security />}
            >
              Leverantörer
            </Button>
            <Button
              variant={activeTab === 'documents' ? 'contained' : 'outlined'}
              onClick={() => setActiveTab('documents')}
              startIcon={<Description />}
            >
              Mina Dokument
            </Button>
          </Box>

          {renderContent()}
        </Container>
      </Box>
    </ThemeProvider>
    </AuthProvider>
  );
}

export default App;