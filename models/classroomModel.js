const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

//Model
const User = require('../models/userModel');
const LineUser = require('../models/lineUserModel');

const classroomSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      default: 'default_classname_name',
      maxlength: [50, 'a name should not be longer than 30 character'],
      minlength: [5, 'a name must be longer than 3 character'],
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
    lineGroupChatId: String,
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

// Cascade Save
classroomSchema.post('save', async function (doc) {
  const user = await LineUser.findById(doc.users[0].userId);
  user.classrooms.push({
    classroomId: doc.id,
    classroomName: doc.name,
    classroomColor: doc.color,
    classroomRole: doc.users[0].classroomRole,
  });
  await user.save();
});

// Cascade Delete
classroomSchema.post('findOneAndDelete', async function (doc) {
  const user = await LineUser.findById(doc.users[0].userId);
  user.classrooms = user.classrooms.filter((el) => doc.id !== el.classroomId);

  await user.save();
});

const Classroom = mongoose.model('Classroom', classroomSchema);

module.exports = Classroom;
