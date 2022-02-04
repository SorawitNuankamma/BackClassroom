const Content = require('../models/contentModel');
const APIFeatures = require('../utils/apifeatures');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Adminstator API
//ROUTE HANDLER
exports.getAllContents = catchAsync(async (req, res, next) => {
  // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
  const features = new APIFeatures(Content.find(), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();
  const contents = await features.query;

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    data: {
      contents,
    },
  });
});

exports.getContent = catchAsync(async (req, res, next) => {
  const content = await Content.findById(req.params.id);
  if (!content) {
    return next(new AppError('no Content found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      content,
    },
  });
});

exports.postContent = catchAsync(async (req, res, next) => {
  const newContent = await Content.create(req.body);

  res.status(200).json({
    status: 'success',
    data: {
      newContent,
    },
  });
});

exports.updateContent = catchAsync(async (req, res, next) => {
  const content = await Content.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!content) {
    return next(new AppError('no Content found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      content,
    },
  });
});

exports.deleteContent = catchAsync(async (req, res, next) => {
  const content = await Content.findByIdAndDelete(req.params.id);

  if (!content) {
    return next(new AppError('no Content found with that id', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

// Content public API
exports.updateMyContent = catchAsync(async (req, res, next) => {
  // check condition

  //filter | argument ตามด้วยค่าใน DB ที่ Content สามารถเปลี่ยนเองได้
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

  const updateContent = await Content.findByIdAndUpdate(
    req.content.id,
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
      content: updateContent,
    },
  });
});

// Content route

exports.getMyContent = catchAsync(async (req, res, next) => {
  const content = req.content;
  if (!content) {
    return next(new AppError('unknown error', 404));
  }
  res.status(200).json({
    status: 'success',
    data: {
      content,
    },
  });
});
