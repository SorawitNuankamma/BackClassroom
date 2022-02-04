const mongoose = require('mongoose');
const validator = require('validator');

const submissionSchema = new mongoose.Schema(
  {
    comment: {
      type: String,
      default: '',
      maxlength: [100, 'a name should not be longer than 10 character'],
    },
    score: {
      type: Number,
      default: 0,
      min: [0, 'must be more than 0'],
      max: [100, 'must be less or equal to 100'],
    },
    userId: String,
    contentId: String,
    classroomId: String,
    submitDate: String,
    isStudent: Boolean,
    isGraded: {
      type: Boolean,
      default: false,
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Save Date on every save
submissionSchema.pre('save', function (next) {
  this.submitDate = Date();
  next();
});

const Submission = mongoose.model('Submission', submissionSchema);

module.exports = Submission;
