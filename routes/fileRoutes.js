const express = require('express');
const fileController = require('../controller/fileController');
const authController = require('../controller/authController');

// create router from express
const router = express.Router();

// Aggreatte route

//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
router.route('/').get(fileController.getAllFiles).post(fileController.postFile);

router
  .route('/:id')
  .get(fileController.getFile)
  .patch(fileController.updateFile)
  .delete(fileController.deleteFile);

module.exports = router;
