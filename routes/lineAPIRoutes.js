const express = require('express');
const lineAPIController = require('../controller/lineAPIController');

// create router from express
const router = express.Router();

// CRUD Route  Authentication | Authorization | Responce
router.route('/postLineMessage').post(lineAPIController.postLineMessage);

router.route('/sendLineMessage').post(lineAPIController.sendLineMessage);

module.exports = router;
