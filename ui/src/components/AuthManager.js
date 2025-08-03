import React, { useState } from 'react';
import {
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  Box,
  Typography,
  CircularProgress,
  Menu,
  MenuItem,
  Avatar
} from '@mui/material';
import { AccountCircle, Logout, Person } from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

const AuthManager = () => {
  const { user, login, register, logout, isAuthenticated } = useAuth();
  const [loginOpen, setLoginOpen] = useState(false);
  const [registerOpen, setRegisterOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [anchorEl, setAnchorEl] = useState(null);
  
  // Login form state
  const [loginForm, setLoginForm] = useState({
    email: '',
    password: ''
  });
  
  // Register form state
  const [registerForm, setRegisterForm] = useState({
    email: '',
    password: '',
    first_name: '',
    last_name: ''
  });

  const handleLogin = async () => {
    setLoading(true);
    setError('');
    
    try {
      await login(loginForm.email, loginForm.password);
      setLoginOpen(false);
      setLoginForm({ email: '', password: '' });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    setLoading(true);
    setError('');
    
    try {
      await register(
        registerForm.email, 
        registerForm.password, 
        registerForm.first_name, 
        registerForm.last_name
      );
      setRegisterOpen(false);
      setRegisterForm({ email: '', password: '', first_name: '', last_name: '' });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    logout();
    setAnchorEl(null);
  };

  const handleMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  if (isAuthenticated && user) {
    return (
      <>
        <Button 
          color="inherit" 
          startIcon={<Avatar sx={{ width: 24, height: 24 }}>{user.first_name[0]}</Avatar>}
          onClick={handleMenuOpen}
        >
          {user.first_name} {user.last_name}
        </Button>
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleMenuClose}
        >
          <MenuItem onClick={handleMenuClose}>
            <Person sx={{ mr: 1 }} />
            Profil
          </MenuItem>
          <MenuItem onClick={handleLogout}>
            <Logout sx={{ mr: 1 }} />
            Logga ut
          </MenuItem>
        </Menu>
      </>
    );
  }

  return (
    <>
      <Button 
        color="inherit" 
        startIcon={<AccountCircle />}
        onClick={() => setLoginOpen(true)}
      >
        Logga in
      </Button>

      {/* Login Dialog */}
      <Dialog open={loginOpen} onClose={() => setLoginOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Logga in</DialogTitle>
        <DialogContent>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          
          <TextField
            fullWidth
            label="E-post"
            type="email"
            margin="normal"
            value={loginForm.email}
            onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })}
            disabled={loading}
          />
          
          <TextField
            fullWidth
            label="Lösenord"
            type="password"
            margin="normal"
            value={loginForm.password}
            onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
            disabled={loading}
            onKeyPress={(e) => {
              if (e.key === 'Enter') {
                handleLogin();
              }
            }}
          />
          
          <Box sx={{ mt: 2 }}>
            <Typography variant="body2">
              Har du inget konto?{' '}
              <Button 
                size="small" 
                onClick={() => {
                  setLoginOpen(false);
                  setRegisterOpen(true);
                }}
              >
                Registrera dig
              </Button>
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setLoginOpen(false)} disabled={loading}>
            Avbryt
          </Button>
          <Button 
            onClick={handleLogin} 
            variant="contained" 
            disabled={loading || !loginForm.email || !loginForm.password}
          >
            {loading ? <CircularProgress size={20} /> : 'Logga in'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Register Dialog */}
      <Dialog open={registerOpen} onClose={() => setRegisterOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Skapa konto</DialogTitle>
        <DialogContent>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          
          <TextField
            fullWidth
            label="E-post"
            type="email"
            margin="normal"
            value={registerForm.email}
            onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })}
            disabled={loading}
          />
          
          <TextField
            fullWidth
            label="Förnamn"
            margin="normal"
            value={registerForm.first_name}
            onChange={(e) => setRegisterForm({ ...registerForm, first_name: e.target.value })}
            disabled={loading}
          />
          
          <TextField
            fullWidth
            label="Efternamn"
            margin="normal"
            value={registerForm.last_name}
            onChange={(e) => setRegisterForm({ ...registerForm, last_name: e.target.value })}
            disabled={loading}
          />
          
          <TextField
            fullWidth
            label="Lösenord"
            type="password"
            margin="normal"
            value={registerForm.password}
            onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })}
            disabled={loading}
          />
          
          <Box sx={{ mt: 2 }}>
            <Typography variant="body2">
              Har du redan ett konto?{' '}
              <Button 
                size="small" 
                onClick={() => {
                  setRegisterOpen(false);
                  setLoginOpen(true);
                }}
              >
                Logga in
              </Button>
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRegisterOpen(false)} disabled={loading}>
            Avbryt
          </Button>
          <Button 
            onClick={handleRegister} 
            variant="contained" 
            disabled={loading || !registerForm.email || !registerForm.password || !registerForm.first_name || !registerForm.last_name}
          >
            {loading ? <CircularProgress size={20} /> : 'Skapa konto'}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default AuthManager;