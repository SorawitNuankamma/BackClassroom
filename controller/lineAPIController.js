const catchAsync = require('../utils/catchAsync');
const line = require('@line/bot-sdk');
const Classroom = require('../models/classroomModel');
const LineUser = require('../models/lineUserModel');

const client = new line.Client({
  channelAccessToken: `0S82MK8Q8Db9CqR4lh26Tr9qoU16U5p4RS0xfIXBEGne7zHYpq7plHgEMCW8TCgss85IrcWwrRdfP5q0VoMHFrOB1850fGdkiw9y0rX61cblBm5KfC/0FDr7yazl+SY7wo4eOcNlF4E74WjZIumo0wdB04t89/1O/w1cDnyilFU=`,
});

const handleConnectClassroom = async (event, accessCode) => {
  const classroom = await Classroom.findOne({ accessCode: accessCode });
  if (!classroom) {
    return {
      type: 'text',
      text: `ไม่พบห้องเรียนที่มีรหัสนั้น โปรดลองใหม่ในภายหลัง หากรอแล้วยังเกิดปัญหาอยู่ โปรดติดต่อฝ่ายสนับสนุนผลิตภัณท์`,
    };
  }
  // find owner lineUserId with the classroom owner id
  const lineUser = await LineUser.findById(classroom.users[0].userId);
  if (!lineUser) {
    return {
      type: 'text',
      text: `ข้อผิดพลาด: สมาชิกไม่ได้เป็นสมาชิกห้องเรียนนั้นๆ`,
    };
  }
  // check if user is owner
  if (event.source.userId !== lineUser.lineUserId) {
    return {
      type: 'text',
      text: `ข้อผิดพลาด: สมาชิกไม่ได้เป็นเจ้าของห้องเรียน`,
    };
  }

  // check if classroom already connected
  if (classroom.lineGroupChatId || classroom.lineGroupChatId === '') {
    return {
      type: 'text',
      text: `ข้อผิดพลาด: ห้องเรียนนี้ถูกเชื่อมต่อกับกลุ่มสนทนาเรียบร้อยแล้ว`,
    };
  }
  // save groupchatId to classroom
  let code = classroom.accessCode;
  classroom.lineGroupChatId = event.source.groupId;
  classroom.save();
  return [
    {
      type: 'text',
      text: `เชื่อมต่อกับห้องเรียน ${classroom.name} สำเร็จ`,
    },
    {
      type: 'template',
      altText: `เข้าร่วมห้องเรียน`,
      template: {
        type: 'buttons',
        thumbnailImageUrl:
          'https://cdn.filestackcontent.com/r7txgd1rTAy66EcL5Ft7',
        imageAspectRatio: 'rectangle',
        imageSize: 'cover',
        imageBackgroundColor: '#FFFFFF',
        title: `เข้าร่วมห้องเรียนใหม่`,
        text: `สามารถเข้าร่วมห้องเรียนได้ผ่านช่องทางนี้`,
        defaultAction: {
          type: 'uri',
          label: 'View detail',
          uri: `https://liff.line.me/1656696595-3dzBR2wb/authentication?loginTo=/app/join-classroom?code=${code}`,
        },
        actions: [
          {
            type: 'uri',
            label: 'ดูเนื้อหา',
            uri: `https://liff.line.me/1656696595-3dzBR2wb/authentication?loginTo=/app/join-classroom?code=${code}`,
          },
        ],
      },
    },
  ];
};

const commandBlock = {
  connect: handleConnectClassroom,
  test: () => {
    return {
      type: 'text',
      text: 'ทดสอบ 123',
    };
  },
  testButton: () => {
    return {
      type: 'template',
      altText: 'This is a buttons template',
      template: {
        type: 'buttons',
        thumbnailImageUrl: 'https://example.com/bot/images/image.jpg',
        imageAspectRatio: 'rectangle',
        imageSize: 'cover',
        imageBackgroundColor: '#FFFFFF',
        title: 'Menu',
        text: '  ',
        defaultAction: {
          type: 'uri',
          label: 'View detail',
          uri: 'http://example.com/page/123',
        },
        actions: [
          {
            type: 'uri',
            label: 'ดูเนื้อหา',
            uri: 'http://example.com/page/123',
          },
        ],
      },
    };
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
    let message = {
      type: 'text',
      text: 'dd',
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
      try {
        message = await commandBlock[command[0]](event, command[1]);
      } catch (e) {
        console.log(e);
      }
    }
    if (message.text !== '') {
      try {
        await client.replyMessage(`${event.replyToken}`, message);
      } catch (e) {
        console.log(e);
      }
    }
  });

  await Promise.all(promises);

  res.status(200).json({
    status: 'success',
  });
});
