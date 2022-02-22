const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Scheduler = require('./models/schedulerModel');
const schedule = require('node-schedule');
const utility = require('./utils/utility');

process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT REJECTION !!! SHUTTING DOWN');
  console.log(err.name, err.message);
  process.exit(1);
});

dotenv.config({ path: './config.env' });
const app = require('./app');

const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

// replace DB with process.env.DATABASE_LOCAL for local database
mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    autoIndex: true,
    useFindAndModify: false,
  })
  .then(() => {
    console.log('DB connection successful');
  });

const port = process.env.PORT || 5000;
const server = app.listen(port, () => {
  console.log(`app running on port ${port}`);
});

process.on('unhandledRejection', (err) => {
  console.log(err.name, err.message);
  console.log('UNHANDLE REJECTION !!! SHUTTING DOWN');
  server.close(() => {
    process.exit(1);
  });
});

// turn on all scheduler

// Better implement this by cancel this job instead
// but this project wont scale. so there is no reason to use it
Scheduler.find().then(async (schedulers) => {
  schedulers.forEach((scheduler) => {
    schedule.scheduleJob(scheduler.scheduleAt, async function () {
      // fetching current scheduler state
      let currentScheduler = await Scheduler.findById(scheduler.id);
      // if it not disable then run it
      if (!currentScheduler.isDisabled) {
        await utility.callback[scheduler.event](scheduler.message);
      }
    });
  });
});
