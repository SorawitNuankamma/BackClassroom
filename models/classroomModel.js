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
      minlength: [3, 'a name must be longer than 3 character'],
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
    isJustCreate: {
      type: Boolean,
      default: true,
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

  // Add user to be owner in this classroom
  const user = await LineUser.findById(this.users[0].userId);
  user.classrooms.push({
    classroomName: this.name,
    classroomColor: this.color,
    classroomRole: this.users[0].classroomRole,
    lineUserId: this.users.lineUserId,
    studentCode: '999',
    email: 'none',
  });
  await user.save();

  next();
});

// Cascade Save
classroomSchema.post('save', async function (doc) {
  if (doc.lineGroupChatId) {
    // remove scheduler related to this classroom
    const oldSchedulers = await Scheduler.find({ owner: doc.id });
    const deletePromises = oldSchedulers.map(async (scheduler, index) => {
      await Scheduler.findByIdAndDelete(scheduler.id);
    });
    await Promise.all(deletePromises);

    // Create Schedule for each time in class
    const promises = this.timetable.map(async (time, index) => {
      let newScheduler = {
        name: `${doc.id}:classnotify:${index}`,
        scheduleAt: `${trimZero(time[1].start.split(':')[1])} ${trimZero(
          time[1].start.split(':')[0]
        )} * * ${timeValue[time[0]]}`,
        event: 'notify',
        isDisabled: false,
        message: `${doc.meetingLink}`,
        messageType: 'template',
        target: doc.lineGroupChatId,
        owner: doc.id,
      };
      console.log(newScheduler);

      await Scheduler.create(newScheduler);
    });
    await Promise.all(promises);
  }
});

// Cascade Delete
classroomSchema.post('findOneAndDelete', async function (doc) {
  const user = await LineUser.findById(doc.users[0].userId);
  user.classrooms = user.classrooms.filter((el) => doc.id !== el.classroomId);

  await user.save();
});

const Classroom = mongoose.model('Classroom', classroomSchema);

module.exports = Classroom;
