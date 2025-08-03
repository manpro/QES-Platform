import React, { useState, useCallback } from 'react';
import {
  Paper,
  Typography,
  Button,
  Box,
  Alert,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  IconButton,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Grid
} from '@mui/material';
import {
  CloudUpload,
  Description,
  Delete,
  Send
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';

const DocumentUploader = () => {
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [signatureFormat, setSignatureFormat] = useState('PAdES-LTA');
  const [provider, setProvider] = useState('');

  const onDrop = useCallback((acceptedFiles) => {
    setFiles(prev => [...prev, ...acceptedFiles.map(file => ({
      file,
      id: Math.random().toString(36).substr(2, 9),
      name: file.name,
      size: file.size,
      status: 'ready'
    }))]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'application/msword': ['.doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx']
    }
  });

  const removeFile = (id) => {
    setFiles(prev => prev.filter(f => f.id !== id));
  };

  const uploadDocuments = async () => {
    if (files.length === 0 || !provider) {
      alert('Välj filer och leverantör först');
      return;
    }

    setUploading(true);
    
    let successCount = 0;
    let errorCount = 0;
    
    for (const fileItem of files) {
      try {
        setFiles(prev => prev.map(f => 
          f.id === fileItem.id ? { ...f, status: 'uploading' } : f
        ));

        const formData = new FormData();
        formData.append('file', fileItem.file);
        formData.append('display_name', fileItem.file.name);
        formData.append('description', `Dokument för signering med ${provider}`);
        formData.append('tags', signatureFormat);

        const response = await fetch('http://localhost:8000/api/v1/documents/upload', {
          method: 'POST',
          body: formData
        });

        if (response.ok) {
          const result = await response.json();
          console.log('Document uploaded:', result);
          setFiles(prev => prev.map(f => 
            f.id === fileItem.id ? { ...f, status: 'completed', documentId: result.document_id } : f
          ));
          successCount++;
        } else {
          const error = await response.json();
          if (response.status === 409) {
            throw new Error(`Dokumentet finns redan: ${error.detail}`);
          }
          throw new Error(error.detail || 'Upload failed');
        }
      } catch (error) {
        console.error('Upload error:', error);
        setFiles(prev => prev.map(f => 
          f.id === fileItem.id ? { ...f, status: 'error', error: error.message } : f
        ));
        errorCount++;
      }
    }
    
    setUploading(false);
    
    // Use actual counts from upload loop, not state (which updates async)
    if (successCount > 0 && errorCount === 0) {
      alert(`${successCount} fil(er) uppladdade! Gå till "Mina Dokument" för att se och signera dina filer.`);
    } else if (successCount > 0 && errorCount > 0) {
      alert(`${successCount} fil(er) uppladdade, ${errorCount} fel. Kontrollera felen ovan.`);
    } else {
      alert(`Uppladdning misslyckades för alla filer. Kontrollera felen ovan.`);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'ready': return 'primary';
      case 'uploading': return 'warning';
      case 'completed': return 'success';
      case 'error': return 'error';
      default: return 'default';
    }
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Ladda upp Dokument
      </Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel>Signaturformat</InputLabel>
            <Select
              value={signatureFormat}
              label="Signaturformat"
              onChange={(e) => setSignatureFormat(e.target.value)}
            >
              <MenuItem value="PAdES-LTA">PAdES-LTA (PDF)</MenuItem>
              <MenuItem value="XAdES-LTA">XAdES-LTA (XML)</MenuItem>
              <MenuItem value="PAdES-B">PAdES-B (PDF Basic)</MenuItem>
              <MenuItem value="XAdES-B">XAdES-B (XML Basic)</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel>QES-leverantör</InputLabel>
            <Select
              value={provider}
              label="QES-leverantör"
              onChange={(e) => setProvider(e.target.value)}
            >
              <MenuItem value="freja-se">Freja eID (Sverige)</MenuItem>
              <MenuItem value="dtrust-de">D-Trust (Tyskland)</MenuItem>
              <MenuItem value="fnmt-es">FNMT (Spanien)</MenuItem>
              <MenuItem value="itsme-be">itsme (Belgien)</MenuItem>
              <MenuItem value="certinomis-fr">Certinomis (Frankrike)</MenuItem>
            </Select>
          </FormControl>
        </Grid>
      </Grid>

      <Box
        {...getRootProps()}
        sx={{
          border: '2px dashed #ccc',
          borderRadius: 2,
          p: 4,
          textAlign: 'center',
          cursor: 'pointer',
          backgroundColor: isDragActive ? '#f0f0f0' : 'transparent',
          mb: 3,
          '&:hover': {
            backgroundColor: '#f9f9f9'
          }
        }}
      >
        <input {...getInputProps()} />
        <CloudUpload sx={{ fontSize: 48, color: '#ccc', mb: 2 }} />
        <Typography variant="h6" gutterBottom>
          {isDragActive ? 'Släpp filerna här...' : 'Dra filer hit eller klicka för att välja'}
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Stödda format: PDF, DOC, DOCX
        </Typography>
      </Box>

      {files.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            Valda filer ({files.length})
          </Typography>
          <List>
            {files.map((fileObj) => (
              <ListItem
                key={fileObj.id}
                sx={{
                  border: 1,
                  borderColor: 'divider',
                  borderRadius: 1,
                  mb: 1
                }}
              >
                <ListItemIcon>
                  <Description color={getStatusColor(fileObj.status)} />
                </ListItemIcon>
                <ListItemText
                  primary={fileObj.name}
                  secondary={
                    fileObj.status === 'error' && fileObj.error 
                      ? `${Math.round(fileObj.size / 1024)} KB - FEL: ${fileObj.error}`
                      : `${Math.round(fileObj.size / 1024)} KB - ${fileObj.status}`
                  }
                />
                {fileObj.status === 'uploading' && (
                  <LinearProgress sx={{ width: 100, mr: 1 }} />
                )}
                {fileObj.status !== 'uploading' && (
                  <IconButton 
                    onClick={() => removeFile(fileObj.id)}
                    title="Ta bort från lista (raderas ej från Mina Dokument)"
                  >
                    <Delete />
                  </IconButton>
                )}
              </ListItem>
            ))}
          </List>
        </Box>
      )}

      {files.length > 0 && (
        <Box display="flex" gap={2}>
          <Button
            variant="contained"
            startIcon={<Send />}
            onClick={uploadDocuments}
            disabled={uploading || !provider}
            size="large"
          >
            {uploading ? 'Laddar upp...' : `Ladda upp ${files.length} fil(er)`}
          </Button>
          <Button
            variant="outlined"
            onClick={() => setFiles([])}
            disabled={uploading}
          >
            Rensa alla
          </Button>
        </Box>
      )}

      {!provider && files.length > 0 && (
        <Alert severity="warning" sx={{ mt: 2 }}>
          Välj en QES-leverantör för att fortsätta med signeringen.
        </Alert>
      )}
    </Paper>
  );
};

export default DocumentUploader;