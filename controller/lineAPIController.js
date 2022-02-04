const catchAsync = require('../utils/catchAsync');
const line = require('@line/bot-sdk');
const Classroom = require('../models/classroomModel');
const LineUser = require('../models/lineUserModel');

const client = new line.Client({
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
});

const handleConnectClassroom = async (event, accessCode) => {
  const classroom = await Classroom.findOne({ accessCode: accessCode });
  if (!classroom) {
    return `ไม่พบห้องเรียนที่มีรหัสนั้น โปรดลองใหม่ในภายหลัง หากรอแล้วยังเกิดปัญหาอยู่ โปรดติดต่อฝ่ายสนับสนุนผลิตภัณท์`;
  }
  // find owner lineUserId with the classroom owner id
  const lineUser = await LineUser.findById(classroom.users[0].userId);
  if (!lineUser) {
    return `ข้อผิดพลาด: สมาชิกไม่ได้เป็นสมาชิกห้องเรียนนั้นๆ`;
  }
  // check if user is owner
  if (event.source.userId !== lineUser.lineUserId) {
    return `ข้อผิดพลาด: สมาชิกไม่ได้เป็นเจ้าของห้องเรียน`;
  }

  // check if classroom already connected
  if (classroom.lineGroupChatId) {
    return `ข้อผิดพลาด: ห้องเรียนนี้ถูกเชื่อมต่อกับกลุ่มสนทนาอื่นเรียบร้อยแล้ว`;
  }
  // save groupchatId to classroom
  classroom.lineGroupChatId = event.source.groupId;
  classroom.save();
  return `เชื่อมต่อกับห้องเรียน ${classroom.name} สำเร็จ`;
};

const commandBlock = {
  connect: handleConnectClassroom,
  test: () => {
    return 'ทดสอบ 123';
  },
};

exports.postLineMessage = catchAsync(async (req, res, next) => {
  if (!req.body) {
    res.status(400).json({
      status: 'fail',
    });
  }
  const destination = req.body.destination;
  const events = req.body.events;

  const promises = events.map(async (event) => {
    const message = {
      type: 'text',
      text: '',
    };
    let userMessage = event.message.text.trim();
    if (event.type === 'join') {
      message.text =
        'สวัสดีครับ ผมคือ Smart Classroom bot โดยผมจะทำหน้าที่ในการแจ้งเตือนข่าวสารต่างๆที่เกี่ยวข้องกับห้องเรียน ฝากตัวด้วยนะครับผม';
    }
    if (userMessage.startsWith('$')) {
      // bot command
      let command = userMessage.slice(1, userMessage.length).split(' ');
      // mapping command to each case
      message.text = commandBlock[command[0]](event, command[1]);
    }
    if (message.text !== '') {
      await client.replyMessage(`${event.replyToken}`, message);
    }
  });

  await Promise.all(promises);

  res.status(200).json({
    status: 'success',
  });
});
