const mongoose = require('mongoose');
const validator = require('validator');
const line = require('@line/bot-sdk');

const client = new line.Client({
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
});

const contentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      default: 'default_content_name',
      maxlength: [20, 'a name should not be longer than 10 character'],
      minlength: [3, 'a name must be longer than 3 character'],
      validator: [validator.isAlpha, 'must only contain character'],
    },
    writers: {
      type: Array,
    },
    type: {
      type: String,
      enum: ['annoucement', 'lesson', 'assignment', 'none'],
      default: 'none',
    },
    body: Object,
    classId: String,
    createDate: String,
    lastChangeDate: String,
    dueDate: String,
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// เพิ่มเวลาเปลี่ยน password ครั้งล่าสุดใน database
contentSchema.pre('save', function (next) {
  this.createDate = Date();
  next();
});

const Content = mongoose.model('Content', contentSchema);

module.exports = Content;
