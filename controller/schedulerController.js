const Scheduler = require('../models/schedulerModel');
const APIFeatures = require('../utils/apifeatures');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Adminstator API
//ROUTE HANDLER
exports.getAllSchedulers = catchAsync(async (req, res, next) => {
  // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
  const features = new APIFeatures(Scheduler.find(), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();
  const schedulers = await features.query;

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    data: {
      schedulers,
    },
  });
});

exports.getScheduler = catchAsync(async (req, res, next) => {
  const scheduler = await Scheduler.findById(req.params.id);
  if (!scheduler) {
    return next(new AppError('no Scheduler found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      scheduler,
    },
  });
});

exports.postScheduler = catchAsync(async (req, res, next) => {
  const newScheduler = await Scheduler.create(req.body);

  res.status(200).json({
    status: 'success',
    data: {
      newScheduler,
    },
  });
});

exports.updateScheduler = catchAsync(async (req, res, next) => {
  const scheduler = await Scheduler.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!scheduler) {
    return next(new AppError('no Scheduler found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      scheduler,
    },
  });
});

exports.deleteScheduler = catchAsync(async (req, res, next) => {
  const scheduler = await Scheduler.findByIdAndDelete(req.params.id);

  if (!scheduler) {
    return next(new AppError('no Scheduler found with that id', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

// Scheduler public API
exports.updateMyScheduler = catchAsync(async (req, res, next) => {
  // check condition

  //filter | argument ตามด้วยค่าใน DB ที่ Scheduler สามารถเปลี่ยนเองได้
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

  const updateScheduler = await Scheduler.findByIdAndUpdate(
    req.scheduler.id,
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
      scheduler: updateScheduler,
    },
  });
});

// Scheduler route

exports.getMyScheduler = catchAsync(async (req, res, next) => {
  const scheduler = req.scheduler;
  if (!scheduler) {
    return next(new AppError('unknown error', 404));
  }
  res.status(200).json({
    status: 'success',
    data: {
      scheduler,
    },
  });
});
