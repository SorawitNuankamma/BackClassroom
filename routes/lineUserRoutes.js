const express = require('express');
const lineUserController = require('../controller/lineUserController');
const authController = require('../controller/authController');

// create router from express
const router = express.Router();

router.post('/login', authController.lineLogin);
router.post('/authen', authController.lineAuthen);
router.post('/signup', authController.lineSignUp);

router.post('/isLogin', authController.loginOnly, authController.isLogin);

// CRUD Route  Authentication | Authorization | Responce
router
  .route('/')
  .get(authController.loginOnly, lineUserController.getAllLineUsers)
  .post(lineUserController.postLineUser);

router
  .route('/:id')
  .get(lineUserController.getLineUser)
  .patch(lineUserController.updateLineUser)
  .delete(
    authController.protect,
    authController.restrictTo('admin'),
    lineUserController.deleteLineUser
  );

module.exports = router;
