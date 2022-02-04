const Submission = require('../models/submissionModel');
const File = require('../models/fileModel');
const APIFeatures = require('../utils/apifeatures');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const Classroom = require('../models/classroomModel');

// Adminstator API
//ROUTE HANDLER
exports.getAllSubmissions = catchAsync(async (req, res, next) => {
  // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
  const features = new APIFeatures(Submission.find(), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();
  const submissions = await features.query;

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    data: {
      submissions,
    },
  });
});

exports.getSubmission = catchAsync(async (req, res, next) => {
  const submission = await Submission.findById(req.params.id);
  if (!submission) {
    return next(new AppError('no Submission found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      submission,
    },
  });
});

exports.postSubmission = catchAsync(async (req, res, next) => {
  const newSubmission = await Submission.create(req.body);

  res.status(200).json({
    status: 'success',
    data: {
      newSubmission,
    },
  });
});

exports.updateSubmission = catchAsync(async (req, res, next) => {
  const submission = await Submission.findByIdAndUpdate(
    req.params.id,
    req.body,
    {
      new: true,
      runValidators: true,
    }
  );

  if (!submission) {
    return next(new AppError('no Submission found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      submission,
    },
  });
});

exports.deleteSubmission = catchAsync(async (req, res, next) => {
  const submission = await Submission.findByIdAndDelete(req.params.id);

  if (!submission) {
    return next(new AppError('no Submission found with that id', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

// Submission public API
exports.updateMySubmission = catchAsync(async (req, res, next) => {
  // check condition

  //filter | argument ตามด้วยค่าใน DB ที่ Submission สามารถเปลี่ยนเองได้
  /*
  const filterdBody = filterObject(
    req.body,
    'name',
    'color',
    'users',
    'rules',
    'grader',
    'calender',
    'timetable',
    'description'
  );*/

  const updateSubmission = await Submission.findByIdAndUpdate(
    req.submission.id,
    req.body,
    {
      new: true,
      runValidators: true,
    }
  );

  //update document

  res.status(200).json({
    status: 'success',
    data: {
      submission: updateSubmission,
    },
  });
});

exports.getMySubmission = catchAsync(async (req, res, next) => {
  const submission = await Submission.findOne({
    userId: req.user.id,
    contentId: req.body.contentId,
  });

  if (!submission) {
    return next(new AppError('submission not found', 400));
  }

  res.status(200).json({
    status: 'success',
    data: {
      submission,
    },
  });
});

exports.getAllSubmissionsAndFile = catchAsync(async (req, res, next) => {
  // check query
  if (!req.query.contentId) {
    return next(new AppError('bad request', 400));
  }

  // get submission
  const submissions = await Submission.find({ contentId: req.query.contentId });

  // get classroom
  // all submission are in the same classroom
  const classroom = await Classroom.findById(submissions[0].classroomId);
  const members = classroom.users;

  const files = await File.find({
    contentId: req.query.contentId,
  });

  const submissionsAndFiles = [];

  submissions.forEach((el) => {
    const tempObject = {
      member: {},
      id: el.id,
      comment: el.comment,
      score: el.score,
      isGraded: el.isGraded,
      userId: el.userId,
      contentId: el.contentId,
      classroomId: el.classroomId,
      isStudent: el.isStudent,
      submitDate: el.submitDate,
      files: [],
    };
    members.forEach((member) => {
      if (member.userId === el.userId) {
        tempObject.member = member;
      }
    });
    files.forEach((file) => {
      if (file.submissionId === el.id) {
        tempObject.files.push(file);
      }
    });
    submissionsAndFiles.push(tempObject);
  });

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    data: {
      submissionsAndFiles,
    },
  });
});
