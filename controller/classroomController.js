const Classroom = require('../models/classroomModel');
const APIFeatures = require('../utils/apifeatures');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

exports.formatPostRequest = catchAsync(async (req, res, next) => {
  //Validate data
  //packing data
  const classroomObject = {
    name: req.body.name,
    description: req.body.description,
    color: req.body.color,
    users: [],
    rules: req.body.rules,
    grader: [],
    calender: [],
    timetable: {
      mon: [],
      tue: [],
      wed: [],
      thu: [],
      fri: [],
      sat: [],
      sun: [],
    },
  };

  // fill grader
  // fill timetable
  req.body.timetable.forEach((el) => {
    let day = el[0];
    switch (day) {
      case 'Monday':
        classroomObject.timetable.mon.push(el[1]);
        break;
      case 'Tuesday':
        classroomObject.timetable.tue.push(el[1]);
        break;
      case 'Wednesday':
        classroomObject.timetable.wed.push(el[1]);
        break;
      case 'Thursday':
        classroomObject.timetable.thu.push(el[1]);
        break;
      case 'Friday':
        classroomObject.timetable.fri.push(el[1]);
        break;
      case 'Saturday':
        classroomObject.timetable.sat.push(el[1]);
        break;
      case 'Sunday':
        classroomObject.timetable.sun.push(el[1]);
        break;
      default:
        break;
    }
  });

  classroomObject.users.push({
    userId: req.user.id,
    name: req.user.name,
    classroomRole: 'owner',
  });
  req.body = classroomObject;

  next();
});

// Adminstator API
//ROUTE HANDLER
exports.getAllClassrooms = catchAsync(async (req, res, next) => {
  // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
  const features = new APIFeatures(Classroom.find(), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();
  const classrooms = await features.query;

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    data: {
      classrooms,
    },
  });
});

exports.getClassroom = catchAsync(async (req, res, next) => {
  const classroom = await Classroom.findById(req.params.id);
  if (!classroom) {
    return next(new AppError('no Classroom found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      classroom,
    },
  });
});

exports.postClassroom = catchAsync(async (req, res, next) => {
  const newClassroom = await Classroom.create(req.body);

  res.status(200).json({
    status: 'success',
    data: {
      newClassroom,
    },
  });
});

exports.updateClassroom = catchAsync(async (req, res, next) => {
  const classroom = await Classroom.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!classroom) {
    return next(new AppError('no Classroom found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      classroom,
    },
  });
});

exports.deleteClassroom = catchAsync(async (req, res, next) => {
  const classroom = await Classroom.findByIdAndDelete(req.params.id);

  if (!classroom) {
    return next(new AppError('no Classroom found with that id', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

// Classroom public API
exports.updateMyClassroom = catchAsync(async (req, res, next) => {
  // check condition
  if (req.body.accessCode) {
    return next(new AppError('cannot change access code', 400));
  }

  //filter | argument ตามด้วยค่าใน DB ที่ Classroom สามารถเปลี่ยนเองได้
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
  );
  const updateClassroom = await Classroom.findByIdAndUpdate(
    req.Classroom.id,
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
      Classroom: updateClassroom,
    },
  });
});

// Classroom route

exports.getMyClassroom = catchAsync(async (req, res, next) => {
  const classroom = req.Classroom;
  if (!classroom) {
    return next(new AppError('unknown error', 404));
  }
  res.status(200).json({
    status: 'success',
    data: {
      classroom,
    },
  });
});
