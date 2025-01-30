const multer = require('multer');
const path = require('path');
const sanitize = require('sanitize-filename');


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); 
    },
    filename: (req, file, cb) => {
        const sanitizedFilename = sanitize(file.originalname); // Sanitize filename
        cb(null, `${Date.now()}-${sanitizedFilename}`);
    }
});


const fileFilter = (req, file, cb) => {
    const allowedExtensions = ['.docx', '.txt', '.pdf'];
    const allowedMimeTypes = [
        'application/msword', // .doc
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // .docx
        'text/plain', // .txt
        'application/pdf' // .pdf
    ];
    const ext = path.extname(file.originalname).toLowerCase();

    if (allowedExtensions.includes(ext) && allowedMimeTypes.includes(file.mimetype)) {
        cb(null, true); // Accept file
    } else {
        cb(new Error('Invalid file type. Only .docx, .txt, and .pdf are allowed.'), false); // Reject file
    }
};

// Configure Multer
const upload = multer({
    storage,
    fileFilter,
    limits: {
        fileSize: 2 * 1024 * 1024 // Limit file size to 2MB
    }
}).fields([
    { name: 'relatedDocuments', maxCount: 5 },
    { name: 'requestLetterDocuments', maxCount: 5 }
]);

module.exports = upload;
