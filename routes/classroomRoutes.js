const express = require('express');
const classroomController = require('../controller/classroomController');
const authController = require('../controller/authController');

// create router from express
const router = express.Router();

// Normal route
router.get(
  '/getMyClassroom',
  authController.protect,
  classroomController.getMyClassroom
);

router.patch(
  '/updateMyClassroom',
  authController.protect,
  classroomController.updateMyClassroom
);

// Aggreatte route

//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
router
  .route('/')
  .get(classroomController.getAllClassrooms)
  .post(
    authController.protect,
    classroomController.formatPostRequest,
    classroomController.postClassroom
  );

router
  .route('/:id')
  .get(classroomController.getClassroom)
  .patch(classroomController.updateClassroom)
  .delete(classroomController.deleteClassroom);

module.exports = router;
