const mongoose = require('mongoose');
const validator = require('validator');

const fileSchema = new mongoose.Schema(
  {
    filename: {
      type: String,
      default: 'default_content_name',
    },
    fileStackURL: String,
    fileStackHandle: String,
    size: Number,
    mimetype: String,
    fileStackUploadId: String,
    uploadDate: String,
    submissionId: String,
    contentId: String,
    isDeleted: {
      type: Boolean,
      default: false,
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// เพิ่มเวลาสร้าง
fileSchema.pre('save', function (next) {
  this.uploadDate = Date();
  next();
});

const File = mongoose.model('File', fileSchema);

module.exports = File;
