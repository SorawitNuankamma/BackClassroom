const mongoose = require('mongoose');
const validator = require('validator');
const line = require('@line/bot-sdk');
const Classroom = require('./classroomModel');

const client = new line.Client({
  channelAccessToken: `0S82MK8Q8Db9CqR4lh26Tr9qoU16U5p4RS0xfIXBEGne7zHYpq7plHgEMCW8TCgss85IrcWwrRdfP5q0VoMHFrOB1850fGdkiw9y0rX61cblBm5KfC/0FDr7yazl+SY7wo4eOcNlF4E74WjZIumo0wdB04t89/1O/w1cDnyilFU=`,
});

const thumbnailImageOf = {
  annoucement: 'https://cdn.filestackcontent.com/RrUSnQlRLaStAHRdYZgD',
  lesson: 'https://cdn.filestackcontent.com/L1DTK4BT1CISu4Nqx2Dn',
  assignment: 'https://cdn.filestackcontent.com/2UEXq3mQyeVPqyyUlADO',
};

const titleOf = {
  annoucement: 'ประกาศใหม่จากห้องเรียน',
  lesson: 'บทเรียนใหม่',
  assignment: 'แบบฝึกหัดใหม่',
};

const contentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      default: 'default_content_name',
      maxlength: [20, 'a name should not be longer than 10 character'],
      minlength: [3, 'a name must be longer than 3 character'],
      validator: [validator.isAlpha, 'must only contain character'],
    },
    writers: {
      type: Array,
    },
    type: {
      type: String,
      enum: ['annoucement', 'lesson', 'assignment', 'none'],
      default: 'none',
    },
    body: Object,
    classId: String,
    createDate: String,
    lastChangeDate: String,
    dueDate: String,
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// เพิ่มเวลาเปลี่ยน password ครั้งล่าสุดใน database
contentSchema.pre('save', async function (next) {
  this.createDate = Date();

  next();
});

contentSchema.post('save', async function (doc) {
  // send message to line group
  let classroom = await Classroom.findById(doc.classId);
  if (classroom.lineGroupChatId || classroom.lineGroupChatId !== '') {
    let message = {
      type: 'template',
      altText: 'This is a buttons template',
      template: {
        type: 'buttons',
        thumbnailImageUrl: thumbnailImageOf[doc.type],
        imageAspectRatio: 'rectangle',
        imageSize: 'cover',
        imageBackgroundColor: '#FFFFFF',
        title: `${titleOf[doc.type]}`,
        text: `${doc.title}`,
        defaultAction: {
          type: 'uri',
          label: 'View detail',
          uri: `https://liff.line.me/1656907747-ZYdAAnyB/authentication?loginTo=app/my-classroom/${doc.classId}/classroom-lesson/${doc.id}`,
        },
        actions: [
          {
            type: 'uri',
            label: 'ดูเนื้อหา',
            uri: `https://liff.line.me/1656907747-ZYdAAnyB/authentication?loginTo=app/my-classroom/${doc.classId}/classroom-lesson/${doc.id}`,
          },
        ],
      },
    };
    try {
      await client.pushMessage(classroom.lineGroupChatId, message);
    } catch (e) {
      console.log(e);
    }
  }
});

const Content = mongoose.model('Content', contentSchema);

module.exports = Content;
