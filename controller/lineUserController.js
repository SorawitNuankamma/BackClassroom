const LineUser = require('../models/lineUserModel');
const APIFeatures = require('../utils/apifeatures');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const utility = require('../utils/utility');

// Adminstator API
//ROUTE HANDLER

exports.getAllLineUsers = catchAsync(async (req, res, next) => {
  // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
  const features = new APIFeatures(LineUser.find(), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();
  const lineUsers = await features.query;

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    data: {
      lineUsers,
    },
  });
});

exports.getLineUser = catchAsync(async (req, res, next) => {
  const user = await LineUser.findById(req.params.id);
  if (!user) {
    return next(new AppError('no user found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });
});

exports.postLineUser = catchAsync(async (req, res, next) => {
  const newLineUser = await LineUser.create(req.body);

  res.status(200).json({
    status: 'success',
    data: {
      newLineUser,
    },
  });
});

exports.updateLineUser = catchAsync(async (req, res, next) => {
  const user = await LineUser.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!user) {
    return next(new AppError('no user found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });
});

exports.deleteLineUser = catchAsync(async (req, res, next) => {
  const user = await LineUser.findByIdAndDelete(req.params.id);

  if (!user) {
    return next(new AppError('no user found with that id', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

exports.getLineUserStats = catchAsync(async (req, res, next) => {
  const stats = await LineUser.aggregate([
    {
      $match: { number: { $gte: 3 } },
    },
    {
      $group: {
        _id: '$email',
        num: { $sum: 1 },
        sumNum: { $sum: '$number' },
        avg: { $avg: '$number' },
        min: { $min: '$number' },
        max: { $max: '$number' },
      },
    },
    {
      $sort: { avg: 1 },
    },
    {
      $match: { _id: { $ne: 'sorawit.nu@ku.th' } },
    },
  ]);
  res.status(200).json({
    status: 'success',
    data: {
      stats,
    },
  });
});

// LineUser public API

exports.updateMyLineUser = catchAsync(async (req, res, next) => {
  //filter | argument ตามด้วยค่าใน DB ที่ user สามารถเปลี่ยนเองได้
  const filterdBody = utility.filterObject(req.body, 'name');
  const updateLineUser = await LineUser.findByIdAndUpdate(
    req.user.id,
    filterdBody,
    {
      new: true,
      runValidators: true,
    }
  );

  //update document

  res.status(200).json({
    status: 'success',
    data: {
      user: updateLineUser,
    },
  });
});

// LineUser route

/**
 * Get the user from the request and return it.
 */
exports.getMyLineUser = catchAsync(async (req, res, next) => {
  const user = req.user;
  if (!user) {
    return next(new AppError('unknown error', 404));
  }
  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });
});
