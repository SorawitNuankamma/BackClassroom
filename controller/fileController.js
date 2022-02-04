const File = require('../models/fileModel');
const APIFeatures = require('../utils/apifeatures');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Adminstator API
//ROUTE HANDLER
exports.getAllFiles = catchAsync(async (req, res, next) => {
  // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
  const features = new APIFeatures(File.find(), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();
  const files = await features.query;

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    data: {
      files,
    },
  });
});

exports.getFile = catchAsync(async (req, res, next) => {
  const file = await File.findById(req.params.id);
  if (!file) {
    return next(new AppError('no File found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      file,
    },
  });
});

exports.postFile = catchAsync(async (req, res, next) => {
  const newFile = await File.create(req.body);

  res.status(200).json({
    status: 'success',
    data: {
      newFile,
    },
  });
});

exports.updateFile = catchAsync(async (req, res, next) => {
  const file = await File.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!file) {
    return next(new AppError('no File found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      file,
    },
  });
});

exports.deleteFile = catchAsync(async (req, res, next) => {
  const file = await File.findByIdAndDelete(req.params.id);

  if (!file) {
    return next(new AppError('no File found with that id', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

// File public API
exports.updateMyFile = catchAsync(async (req, res, next) => {
  // check condition

  //filter | argument ตามด้วยค่าใน DB ที่ File สามารถเปลี่ยนเองได้
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

  const updateFile = await File.findByIdAndUpdate(req.file.id, req.body, {
    new: true,
    runValidators: true,
  });

  //update document

  res.status(200).json({
    status: 'success',
    data: {
      file: updateFile,
    },
  });
});
