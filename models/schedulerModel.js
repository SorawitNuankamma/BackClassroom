const mongoose = require('mongoose');
const schedule = require('node-schedule');
const validator = require('validator');
const utility = require('../utils/utility');

const schedulerSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      unique: true,
    },
    for: {
      type: String,
      enum: ['classroom', 'content'],
      default: 'classroom',
    },
    scheduleAt: String,
    event: {
      type: String,
      enum: ['notify'],
      default: 'notify',
    },
    message: String,
    messageType: {
      type: String,
      enum: ['text', 'sticker', 'template'],
      default: 'text',
    },
    target: String,
    owner: mongoose.Schema.Types.ObjectId,
    createDate: Date,
    isDisabled: {
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
schedulerSchema.pre('save', function (next) {
  this.createDate = Date.now();
  // pick function base on event
  let event = this.event;
  let name = this.name;
  let message = this.message;
  let target = this.target;

  schedule.scheduleJob(`${name}`, this.scheduleAt, async function () {
    await utility.callback[event](message, target);
  });
  // if isDisabled are true then cancel it
  next();
});

// สร้าง schedule หลังจากสร้างตัว schedule

const Schedule = mongoose.model('Scheduler', schedulerSchema);

module.exports = Schedule;
