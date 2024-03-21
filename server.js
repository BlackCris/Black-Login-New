const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs');
const session = require('express-session');
const path = require('path');
const app = express();
const port = 3000;
const usersFilePath = path.join(__dirname, 'users.json');
const blockedUsersFilePath = path.join(__dirname, 'blockedUsers.json');
const loginAttempts = {}; // { ip: { count: Number, unlockTime: Date } }




const LOGIN_ATTEMPT_LIMIT = 3; // 尝试限制次数
const LOCK_TIME = 3 * 60 * 1000; // 锁定时间
const EXTENDED_LOCK_TIME = 7 * 24 * 60 * 60 * 1000; // 扩展锁定时间为1周


const unblockUser = (username) => {
  // 尝试读取blockedUsers.json文件
  if (fs.existsSync(blockedUsersFilePath)) {
      let blockedUsers = JSON.parse(fs.readFileSync(blockedUsersFilePath).toString());

      // 过滤掉要解锁的用户
      blockedUsers = blockedUsers.filter(user => user.username !== username);

      // 保存更新后的blockedUsers.json文件
      fs.writeFileSync(blockedUsersFilePath, JSON.stringify(blockedUsers, null, 2));

      console.log(`${username} has been unblocked.`);
  } else {
      console.log("Blocked users file does not exist.");
  }
};



app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // HTTPS环境下应设为true
}));

app.use(express.static('public'));

app.get('/unblock/:username', (req, res) => {
  const { username } = req.params;
  unblockUser(username);

  // 查找并重置该用户IP相关的封禁状态
  const blockedUsers = JSON.parse(fs.readFileSync(blockedUsersFilePath).toString());
  const userRecord = blockedUsers.find(user => user.username === username);
  if (userRecord && loginAttempts[userRecord.ip]) {
    delete loginAttempts[userRecord.ip];
  }

  res.send(`${username} has been unblocked`);
});



app.get('/', (req, res) => {
  res.redirect('/Register.html'); // 确保这里的文件名与实际文件名大小写匹配
});

const initializeUsersFile = async () => {
  try {
      // 检查文件是否存在
      if (!fs.existsSync(usersFilePath) || fs.readFileSync(usersFilePath).length === 0) {
          const initialUsers = []; // 初始为空数组，你也可以添加一些初始用户
          fs.writeFileSync(usersFilePath, JSON.stringify(initialUsers, null, 2));
          console.log('Users file initialized.');
      }
  } catch (err) {
      console.error('Error initializing users file:', err);
  }
};

initializeUsersFile();

app.post('/register', async (req, res) => {
  try {
      const { username, password } = req.body;

      const data = fs.readFileSync(usersFilePath);
      const users = JSON.parse(data.toString());

      // 检查用户名是否已经存在
      if (users.some(user => user.username === username)) {
          return res.status(400).send('Username already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      users.push({ username, password: hashedPassword });

      fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
      res.redirect('/Login.html'); // 注册成功后重定向到登录页面
  } catch (error) {
      console.error(error);
      res.status(500).send('Server error');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip; // 首先获取IP地址
  const currentAttempt = loginAttempts[ip] || { count: 0, unlockTime: new Date() }; // 然后使用这个IP地址
  
  if (new Date() < currentAttempt.unlockTime) {
    const waitTime = Math.round((currentAttempt.unlockTime - new Date()) / 1000);
    return res.status(429).send(`Please wait ${waitTime} seconds before trying again.`);
  }

  try {
    const data = fs.readFileSync(usersFilePath);
    const users = JSON.parse(data.toString());
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      currentAttempt.count++;
      loginAttempts[ip] = currentAttempt;
      if (req.session) {
        req.session.destroy(); // 销毁会话
      }

      if (currentAttempt.count >= LOGIN_ATTEMPT_LIMIT) {
        currentAttempt.unlockTime = new Date(new Date().getTime() + LOCK_TIME);
        
        const blockedUser = { username, unlockTime: currentAttempt.unlockTime.toISOString(), ip };

        let blockedUsers = [];
        if (fs.existsSync(blockedUsersFilePath)) {
          const blockedData = fs.readFileSync(blockedUsersFilePath);
          blockedUsers = JSON.parse(blockedData.toString());
        }
        blockedUsers.push(blockedUser);
        fs.writeFileSync(blockedUsersFilePath, JSON.stringify(blockedUsers, null, 2));

        return res.status(401).send('Password incorrect. Account locked for 3 minutes.');
      } else {
        return res.status(401).send(`Password incorrect. You have ${LOGIN_ATTEMPT_LIMIT - currentAttempt.count} attempts remaining.`);
      }
    }

    if (loginAttempts[ip]) delete loginAttempts[ip];
    req.session.user = { username: user.username };
    res.redirect('/data.html');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
      if (err) {
          return console.error(err);
      }
      res.redirect('/login.html'); // 登出后重定向到登录页面
  });
});



app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});


// 认证中间件
function requireLogin(req, res, next) {
  if (req.session && req.session.user) {
    // 这里添加验证逻辑，确保req.session.user是有效的
    const data = fs.readFileSync(usersFilePath);
    const users = JSON.parse(data.toString());
    const userExists = users.some(user => user.username === req.session.user.username);
    
    if (userExists) {
      next(); // 用户已登录，且在users文件中存在，继续下一个请求处理
    } else {
      res.redirect('/login.html'); // 用户的会话无效或在users文件中不存在，重定向到登录页面
    }
  } else {
    res.redirect('/login.html'); // 用户未登录，重定向到登录页面
  }
}


// 在提供home.html之前使用认证中间件
app.get('/data.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'private/data.html'));
});

// 私有文件中间件
app.use('/private', requireLogin, express.static('private'));

