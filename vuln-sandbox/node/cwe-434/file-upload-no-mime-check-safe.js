// SAFE: file-upload-no-mime-check — MIME type and extension validated before saving
// Rule: FileUploadNoMimeCheck | CWE-434 | Expected: TrueNegative

const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];

const upload = multer({
  dest: '/tmp/uploads/',
  fileFilter: (req, file, cb) => {
    // SAFE: validate both MIME type and file extension
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype) || !ALLOWED_EXTENSIONS.includes(ext)) {
      return cb(new Error('Only image files are allowed'));
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB limit
});

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ filename: req.file.filename, size: req.file.size });
});

app.listen(3000);
