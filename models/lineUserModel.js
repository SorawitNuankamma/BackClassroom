const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const lineUserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      default: 'default_user_name',
      maxlength: [20, 'a name should not be longer than 10 character'],
      minlength: [3, 'a name must be longer than 3 character'],
      validator: [validator.isAlpha, 'must only contain character'],
    },
    lineUserId: {
      type: String,
      unique: true,
    },
    email: {
      type: String,
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
    pictureURL: String,
    classrooms: {
      type: Array,
      default: [],
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

const LineUser = mongoose.model('LineUser', lineUserSchema);

module.exports = LineUser;
