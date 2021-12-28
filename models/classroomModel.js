const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

//Model
const User = require('../models/userModel');

const classroomSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      default: 'default_classname_name',
      maxlength: [20, 'a name should not be longer than 10 character'],
      minlength: [3, 'a name must be longer than 3 character'],
      validator: [validator.isAlpha, 'must only contain character'],
    },
    description: {
      type: String,
    },
    color: {
      type: String,
      enum: ['red', 'green', 'blue', 'yellow'],
      default: 'green',
    },
    users: Array,
    accessCode: {
      type: String,
      unique: true,
    },
    rules: String,
    grader: Array,
    calender: Array,
    timetable: Array,
    classroomChangedAt: Date,
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Generate accessCode on new
classroomSchema.pre('save', function (next) {
  if (!this.isNew) return next();

  // Generate Room Code
  this.accessCode = crypto.randomBytes(3).toString('hex');

  next();
});

classroomSchema.post('save', async function (doc) {
  const user = await User.findById(doc.users[0].userId);
  user.classroom.push({
    classroomId: doc.id,
    classroomRole: doc.users[0].classroomRole,
  });
  await user.save();
});

classroomSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.classroomChangedAt = Date.now() - 1000;
  next();
});

const Classroom = mongoose.model('Classroom', classroomSchema);

module.exports = Classroom;
