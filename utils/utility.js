const line = require('@line/bot-sdk');

const client = new line.Client({
  channelAccessToken: `0S82MK8Q8Db9CqR4lh26Tr9qoU16U5p4RS0xfIXBEGne7zHYpq7plHgEMCW8TCgss85IrcWwrRdfP5q0VoMHFrOB1850fGdkiw9y0rX61cblBm5KfC/0FDr7yazl+SY7wo4eOcNlF4E74WjZIumo0wdB04t89/1O/w1cDnyilFU=`,
});

/**
 * Filter an object by passing in an array of allowed fields.
 */
exports.filterObject = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) {
      newObj[el] = obj[el];
    }
  });
  return newObj;
};

exports.callback = {
  notify: async (value, target) => {
    let message = {
      type: 'template',
      altText: 'แจ้งเตือนการเริ่มเรียน',
      template: {
        type: 'buttons',
        thumbnailImageUrl:
          'https://cdn.filestackcontent.com/tpwDVvNWTSu3AB27xWe0',
        imageAspectRatio: 'rectangle',
        imageSize: 'cover',
        imageBackgroundColor: '#FFFFFF',
        title: `ถึงเวลาเรียนแล้ว`,
        text: `เข้าห้องเรียนผ่านช่องทางนี้ได้เลย`,
        defaultAction: {
          type: 'uri',
          label: 'View detail',
          uri: `${value}`,
        },
        actions: [
          {
            type: 'uri',
            label: 'ดูเนื้อหา',
            uri: `${value}`,
          },
        ],
      },
    };
    try {
      await client.pushMessage(target, message);
    } catch (e) {
      console.log(e);
    }
  },
};
