import React, { useState, useEffect, useCallback } from 'react';
import {
  Paper,
  Typography,
  Button,
  Box,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  InputAdornment,
  Pagination,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  Divider,
  Tab,
  Tabs
} from '@mui/material';
import {
  Description,
  CloudUpload,
  Download,
  Visibility,
  Delete,
  Search,
  FilterList,
  Verified,
  Schedule,
  Error as ErrorIcon,
  CheckCircle,
  Info,
  Security
} from '@mui/icons-material';
import { format } from 'date-fns';

const DocumentManager = () => {
  const [documents, setDocuments] = useState([]);
  const [signatures, setSignatures] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDocument, setSelectedDocument] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [activeTab, setActiveTab] = useState(0);

  const loadDocuments = useCallback(async () => {
    try {
      const params = new URLSearchParams({
        page: page,
        size: 10,
        ...(searchQuery && { search: searchQuery }),
        ...(statusFilter !== 'all' && { status_filter: statusFilter })
      });

      const response = await fetch(`http://localhost:8000/api/v1/documents?${params}`);
      const data = await response.json();
      
      if (response.ok) {
        setDocuments(data.documents);
        setTotalPages(Math.ceil(data.total / data.size));
      } else {
        console.error('Failed to load documents:', data);
      }
    } catch (error) {
      console.error('Error loading documents:', error);
    } finally {
      setLoading(false);
    }
  }, [page, searchQuery, statusFilter]);

  const loadSignatures = useCallback(async () => {
    try {
      const response = await fetch('http://localhost:8000/api/v1/signatures?size=50');
      const data = await response.json();
      
      if (response.ok) {
        setSignatures(data.signatures);
      } else {
        console.error('Failed to load signatures:', data);
      }
    } catch (error) {
      console.error('Error loading signatures:', error);
    }
  }, []);

  // Effect to load data when component mounts or dependencies change
  useEffect(() => {
    loadDocuments();
    loadSignatures();
  }, [loadDocuments, loadSignatures]);

  const handleDownload = async (documentId, filename) => {
    try {
      const response = await fetch(`http://localhost:8000/api/v1/documents/${documentId}/download`);
      
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      } else {
        console.error('Download failed');
      }
    } catch (error) {
      console.error('Error downloading file:', error);
    }
  };

  const handleSignDocument = async (documentId) => {
    try {
      const response = await fetch('http://localhost:8000/api/v1/signatures/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          document_id: documentId,
          qes_provider: 'freja-se',
          signature_format: 'PAdES-LTA',
          signature_reason: 'Document approval'
        })
      });

      const data = await response.json();
      
      if (response.ok) {
        // TODO: 🟢 Ta bort demo-simulation, använd riktig QES provider callback
        // Simulate signing completion for demo
        setTimeout(async () => {
          await fetch(`http://localhost:8000/api/v1/signatures/sessions/${data.session_id}/simulate-complete`, {
            method: 'POST'
          });
          loadDocuments();
          loadSignatures();
        }, 2000);
        
        alert('Signering påbörjad! Dokumentet kommer att uppdateras inom kort.');
      } else {
        console.error('Signing failed:', data);
        alert('Signering misslyckades: ' + data.detail);
      }
    } catch (error) {
      console.error('Error signing document:', error);
      alert('Fel vid signering');
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'signed':
        return <CheckCircle color="success" />;
      case 'ready':
        return <Schedule color="primary" />;
      case 'processing':
        return <Schedule color="warning" />;
      case 'error':
        return <ErrorIcon color="error" />;
      default:
        return <Info color="info" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'signed': return 'success';
      case 'ready': return 'primary';
      case 'processing': return 'warning';
      case 'error': return 'error';
      default: return 'default';
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const DocumentsTab = () => (
    <Box>
      <Box display="flex" gap={2} mb={3} alignItems="center">
        <TextField
          placeholder="Sök dokument..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          size="small"
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Search />
              </InputAdornment>
            ),
          }}
        />
        <TextField
          select
          label="Status"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          size="small"
          SelectProps={{ native: true }}
          sx={{ minWidth: 120 }}
        >
          <option value="all">Alla</option>
          <option value="ready">Redo</option>
          <option value="signed">Signerad</option>
          <option value="processing">Bearbetas</option>
          <option value="error">Fel</option>
        </TextField>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Dokument</TableCell>
              <TableCell>Storlek</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Signaturer</TableCell>
              <TableCell>Skapad</TableCell>
              <TableCell>Åtgärder</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {documents.map((doc) => (
              <TableRow key={doc.id}>
                <TableCell>
                  <Box display="flex" alignItems="center">
                    <Description sx={{ mr: 1 }} />
                    <Box>
                      <Typography variant="body2" fontWeight="medium">
                        {doc.display_name || doc.filename}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {doc.mime_type}
                      </Typography>
                    </Box>
                  </Box>
                </TableCell>
                <TableCell>{formatFileSize(doc.file_size)}</TableCell>
                <TableCell>
                  <Chip 
                    icon={getStatusIcon(doc.status)}
                    label={doc.status}
                    color={getStatusColor(doc.status)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Box display="flex" alignItems="center">
                    {doc.signature_count > 0 && (
                      <Verified color="success" sx={{ mr: 0.5 }} />
                    )}
                    {doc.signature_count}
                  </Box>
                </TableCell>
                <TableCell>
                  {format(new Date(doc.created_at), 'yyyy-MM-dd HH:mm')}
                </TableCell>
                <TableCell>
                  <Box display="flex" gap={1}>
                    <IconButton 
                      size="small" 
                      onClick={() => {
                        setSelectedDocument(doc);
                        setDialogOpen(true);
                      }}
                      title="Visa detaljer"
                    >
                      <Visibility />
                    </IconButton>
                    <IconButton 
                      size="small" 
                      onClick={() => handleDownload(doc.id, doc.filename)}
                      title="Ladda ner"
                    >
                      <Download />
                    </IconButton>
                    {doc.status === 'ready' && (
                      <Button
                        size="small"
                        variant="contained"
                        startIcon={<Security />}
                        onClick={() => handleSignDocument(doc.id)}
                        color="primary"
                      >
                        Signera
                      </Button>
                    )}
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Box display="flex" justifyContent="center" mt={3}>
        <Pagination 
          count={totalPages} 
          page={page} 
          onChange={(e, value) => setPage(value)}
          color="primary"
        />
      </Box>
    </Box>
  );

  const SignaturesTab = () => (
    <Box>
      <Typography variant="h6" gutterBottom>
        Mina Signaturer ({signatures.length})
      </Typography>
      
      <List>
        {signatures.map((sig, index) => (
          <React.Fragment key={sig.id}>
            <ListItem>
              <ListItemIcon>
                <Security color={sig.is_valid ? 'success' : 'error'} />
              </ListItemIcon>
              <ListItemText
                primary={
                  <Box display="flex" alignItems="center" gap={1}>
                    <Typography variant="body2" fontWeight="medium">
                      {sig.document_filename}
                    </Typography>
                    <Chip 
                      label={sig.status} 
                      color={getStatusColor(sig.status)} 
                      size="small" 
                    />
                  </Box>
                }
                secondary={
                  <Box>
                    <Typography variant="caption" color="textSecondary">
                      {sig.qes_provider} • {sig.signature_format} • {sig.signature_level}
                    </Typography>
                    <br />
                    <Typography variant="caption" color="textSecondary">
                      Signerad: {sig.signature_timestamp ? 
                        format(new Date(sig.signature_timestamp), 'yyyy-MM-dd HH:mm') : 
                        'Väntar'
                      }
                    </Typography>
                  </Box>
                }
              />
              <ListItemSecondaryAction>
                <Box display="flex" alignItems="center" gap={1}>
                  {sig.is_valid && (
                    <Chip label="Giltig" color="success" size="small" />
                  )}
                  <Button size="small" variant="outlined">
                    Detaljer
                  </Button>
                </Box>
              </ListItemSecondaryAction>
            </ListItem>
            {index < signatures.length - 1 && <Divider />}
          </React.Fragment>
        ))}
        
        {signatures.length === 0 && (
          <Box textAlign="center" py={4}>
            <Typography color="textSecondary">
              Inga signaturer ännu. Signera ditt första dokument för att komma igång!
            </Typography>
          </Box>
        )}
      </List>
    </Box>
  );

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Dokumenthanterare
      </Typography>
      
      <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)} sx={{ mb: 3 }}>
        <Tab label={`Dokument (${documents.length})`} />
        <Tab label={`Signaturer (${signatures.length})`} />
      </Tabs>

      {loading ? (
        <Box textAlign="center" py={4}>
          <Typography>Laddar...</Typography>
        </Box>
      ) : (
        <>
          {activeTab === 0 && <DocumentsTab />}
          {activeTab === 1 && <SignaturesTab />}
        </>
      )}

      {/* Document Details Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Dokumentdetaljer</DialogTitle>
        <DialogContent>
          {selectedDocument && (
            <Box>
              <Card sx={{ mb: 2 }}>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    {selectedDocument.display_name || selectedDocument.filename}
                  </Typography>
                  <Box display="flex" gap={4} mb={2}>
                    <Box>
                      <Typography variant="caption" color="textSecondary">Filstorlek</Typography>
                      <Typography>{formatFileSize(selectedDocument.file_size)}</Typography>
                    </Box>
                    <Box>
                      <Typography variant="caption" color="textSecondary">Typ</Typography>
                      <Typography>{selectedDocument.mime_type}</Typography>
                    </Box>
                    <Box>
                      <Typography variant="caption" color="textSecondary">Status</Typography>
                      <Typography>{selectedDocument.status}</Typography>
                    </Box>
                  </Box>
                  
                  {selectedDocument.description && (
                    <Box mb={2}>
                      <Typography variant="caption" color="textSecondary">Beskrivning</Typography>
                      <Typography>{selectedDocument.description}</Typography>
                    </Box>
                  )}
                  
                  {selectedDocument.tags && selectedDocument.tags.length > 0 && (
                    <Box>
                      <Typography variant="caption" color="textSecondary">Taggar</Typography>
                      <Box display="flex" gap={1} flexWrap="wrap" mt={1}>
                        {selectedDocument.tags.map((tag, index) => (
                          <Chip key={index} label={tag} size="small" />
                        ))}
                      </Box>
                    </Box>
                  )}
                </CardContent>
              </Card>
              
              <Typography variant="body2" color="textSecondary">
                Skapad: {format(new Date(selectedDocument.created_at), 'yyyy-MM-dd HH:mm:ss')}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Hash: {selectedDocument.content_hash}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Stäng</Button>
          {selectedDocument && (
            <Button 
              onClick={() => handleDownload(selectedDocument.id, selectedDocument.filename)}
              startIcon={<Download />}
            >
              Ladda ner
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Paper>
  );
};

export default DocumentManager;