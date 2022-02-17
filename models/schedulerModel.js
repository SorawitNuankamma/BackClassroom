const mongoose = require('mongoose');
const schedule = require('node-schedule');
const validator = require('validator');

const callback = {
  notify: (message) => {
    console.log(message);
  },
};

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

  schedule.scheduleJob(`${name}`, this.scheduleAt, function () {
    callback[event](message);
  });
  // if isDisabled are true then cancel it
  next();
});

// สร้าง schedule หลังจากสร้างตัว schedule

const Schedule = mongoose.model('Scheduler', schedulerSchema);

module.exports = Schedule;
