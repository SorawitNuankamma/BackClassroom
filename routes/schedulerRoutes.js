const express = require('express');
const schedulerController = require('../controller/schedulerController');
//const authController = require('../controller/authController');

// create router from express
const router = express.Router();

// Aggreatte route

//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
router
  .route('/')
  .get(schedulerController.getAllSchedulers)
  .post(schedulerController.postScheduler);

router
  .route('/:id')
  .get(schedulerController.getScheduler)
  .patch(schedulerController.updateScheduler)
  .delete(schedulerController.deleteScheduler);

module.exports = router;
