const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const Scheduler = require('./schedulerModel');

//Model
const User = require('../models/userModel');
const LineUser = require('../models/lineUserModel');

const timeValue = {
  Sunday: 0,
  Monday: 1,
  Tuesday: 2,
  Wednesday: 3,
  Thursday: 4,
  Friday: 5,
  Saturday: 6,
};

const trimZero = (str) => {
  if (str.startsWith('0')) {
    return `${str.split('')[1]}`;
  }
  return str;
};

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
      default: '',
    },
    color: {
      type: String,
      enum: ['red', 'green', 'blue', 'yellow'],
      default: 'green',
    },
    users: {
      type: Array,
      default: [],
    },
    accessCode: {
      type: String,
      unique: true,
    },
    rules: String,
    grader: {
      type: Array,
      default: [],
    },
    calender: {
      type: Array,
      default: [],
    },
    timetable: Array,
    lineGroupChatId: String,
    classroomChangedAt: Date,
    notificationOn: {
      type: Object,
      default: {
        startClass: true,
        postingAnnoucement: true,
        postingLesson: true,
        postingAssignment: true,
        assignmentDeadline: true,
      },
    },
    meetingLink: {
      type: String,
      default: '',
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Generate accessCode on new
classroomSchema.pre('save', async function (next) {
  if (!this.isNew) return next();

  // Generate Room Code
  this.accessCode = crypto.randomBytes(3).toString('hex');

  next();
});

// Cascade Save
classroomSchema.post('save', async function (doc) {
  if (!this.isNew) return;

  const user = await LineUser.findById(doc.users[0].userId);
  user.classrooms.push({
    classroomId: doc.id,
    classroomName: doc.name,
    classroomColor: doc.color,
    classroomRole: doc.users[0].classroomRole,
  });

  // Create Schedule for each time in class
  const promises = this.timetable.map(async (time, index) => {
    let newScheduler = {
      name: `${doc.id}:classnotify:${index}`,
      scheduleAt: `${trimZero(time[1].start.split(':')[1])} ${trimZero(
        time[1].start.split(':')[0]
      )} * * ${timeValue[time[0]]}`,
      event: 'notify',
      isDisabled: true,
      message: `ขณะนี้ห้องเรียนได้เริ่มต้นขึ้นแล้ว สามารถเข้าร่วมได้ที่นี้ => ${doc.meetingLink}`,
      owner: doc.id,
    };

    await Scheduler.create(newScheduler);
  });

  await Promise.all(promises);

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
