require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const server = http.createServer(app);

const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST'],
  },
});

const resetSocketIds = async () => {
  try {
    await User.updateMany({}, { $unset: { socketId: '' } });
    console.log('모든 사용자 소켓 ID가 초기화되었습니다.');
  } catch (error) {
    console.error('소켓 ID 초기화 중 오류:', error);
  }
};

// 서버 시작 시 모든 소켓 ID 초기화
resetSocketIds();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
  }),
);

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  })
  .then(() => console.log('MongoDB에 연결되었습니다...'))
  .catch((err) => console.error('MongoDB 연결 오류:', err));

// Middleware for logging requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// User model
const UserSchema = new mongoose.Schema({
  studentId: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  nickname: { type: String, required: true, unique: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  socketId: { type: String },
  isLoggedIn: { type: Boolean, default: false },
  lastLoginAt: { type: Date },
  lastLogoutAt: { type: Date },
});
const User = mongoose.model('User', UserSchema);

// Post model
const PostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
});

const Post = mongoose.model('Post', PostSchema);

// Validation functions
const validateStudentId = (studentId) => {
  return /^\d{10}$/.test(studentId);
};

const validateNickname = (nickname) => {
  const koreanRegex = /^[가-힣]{3}$/;
  return koreanRegex.test(nickname);
};

// Register route
app.post('/register', async (req, res) => {
  try {
    const { studentId, password, nickname } = req.body;

    // 학번 유효성 검사
    if (!validateStudentId(studentId)) {
      return res
        .status(400)
        .json({ success: false, message: '학번은 정확히 10자리 숫자여야 합니다.' });
    }

    // 닉네임 유효성 검사
    if (!validateNickname(nickname)) {
      return res
        .status(400)
        .json({ success: false, message: '닉네임은 정확히 3글자의 한글이어야 합니다.' });
    }

    // 학번 중복 확인
    let user = await User.findOne({ studentId });
    if (user) {
      return res.status(400).json({ success: false, message: '이미 등록된 학번입니다.' });
    }

    // 닉네임 중복 확인
    user = await User.findOne({ nickname });
    if (user) {
      return res.status(400).json({ success: false, message: '이미 사용 중인 닉네임입니다.' });
    }

    // 비밀번호 해싱
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 새 사용자 생성
    user = new User({
      studentId,
      password: hashedPassword,
      nickname,
    });

    await user.save();

    // JWT 토큰 생성
    const token = jwt.sign(
      { id: user._id, studentId: user.studentId, nickname: user.nickname, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' },
    );

    res.json({
      success: true,
      message: '회원가입이 완료되었습니다.',
      token,
      nickname: user.nickname,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
  }
});

// Update user route
app.post('/update-user', authenticateToken, async (req, res) => {
  try {
    const { newNickname, currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }

    const updateFields = {};

    if (newNickname) {
      if (!validateNickname(newNickname)) {
        return res.status(400).json({ message: '닉네임은 정확히 3글자의 한글이어야 합니다.' });
      }

      const existingUser = await User.findOne({ nickname: newNickname, _id: { $ne: userId } });
      if (existingUser) {
        return res.status(400).json({ message: '이미 사용 중인 닉네임입니다.' });
      }

      updateFields.nickname = newNickname;
    }

    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ message: '현재 비밀번호를 입력해주세요.' });
      }

      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: '현재 비밀번호가 일치하지 않습니다.' });
      }

      const salt = await bcrypt.genSalt(10);
      updateFields.password = await bcrypt.hash(newPassword, salt);
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updateFields, { new: true });

    const token = jwt.sign(
      {
        id: updatedUser._id,
        studentId: updatedUser.studentId,
        nickname: updatedUser.nickname,
        role: updatedUser.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' },
    );

    res.json({
      message: '사용자 정보가 성공적으로 업데이트되었습니다.',
      token,
      nickname: updatedUser.nickname,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Student ID check route
app.post('/check-student-id', async (req, res) => {
  try {
    const { studentId } = req.body;

    if (!validateStudentId(studentId)) {
      return res.status(400).json({ message: '학번은 정확히 10자리 숫자여야 합니다.' });
    }

    const user = await User.findOne({ studentId });
    if (user) {
      return res.status(400).json({ message: '이미 등록된 학번입니다.' });
    }

    res.json({ message: '사용 가능한 학번입니다.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Nickname check route
app.post('/check-nickname', async (req, res) => {
  try {
    const { nickname } = req.body;

    if (!validateNickname(nickname)) {
      return res.status(400).json({ message: '닉네임은 정확히 3글자의 한글이어야 합니다.' });
    }

    const user = await User.findOne({ nickname });
    if (user) {
      return res.status(400).json({ message: '이미 사용 중인 닉네임입니다.' });
    }

    res.json({ message: '사용 가능한 닉네임입니다.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 로그인 라우트 수정
app.post('/login', async (req, res) => {
  try {
    const { studentId, password } = req.body;
    const user = await User.findOne({ studentId });

    if (!user) {
      return res.status(401).json({ message: '학번 또는 비밀번호가 올바르지 않습니다.' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: '학번 또는 비밀번호가 올바르지 않습니다.' });
    }

    // 로그인 상태 업데이트
    await User.findByIdAndUpdate(user._id, {
      isLoggedIn: true,
      lastLoginAt: new Date(),
    });

    const token = jwt.sign(
      {
        id: user._id,
        studentId: user.studentId,
        nickname: user.nickname,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' },
    );

    // 로그인 상태 콘솔에 출력
    console.log('User logged in:', {
      studentId: user.studentId,
      nickname: user.nickname,
      isLoggedIn: true,
      lastLoginAt: new Date(),
    });

    res.json({
      token,
      nickname: user.nickname,
      role: user.role,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 로그아웃 라우트 추가
app.post('/logout', authenticateToken, async (req, res) => {
  const studentId = req.user.studentId;
  try {
    await User.findOneAndUpdate({ studentId }, { isLoggedIn: false, $unset: { socketId: '' } });
    res.json({ message: '로그아웃되었습니다.' });
  } catch (error) {
    console.error('로그아웃 오류:', error);
    res.status(500).json({ message: '서버 오류 발생했습니다.' });
  }
});

// Posts routes
app.get('/api/posts', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const posts = await Post.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate('author', 'nickname');

    const totalPosts = await Post.countDocuments();

    res.json({
      posts,
      totalPages: Math.ceil(totalPosts / limit),
      currentPage: page,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const newPost = new Post({
      title,
      content,
      author: req.user.id,
    });
    await newPost.save();
    res.status(201).json({ message: '게시물이 성공적으로 생성되었습니.', post: newPost });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id).populate('author', 'nickname');
    if (!post) {
      return res.status(404).json({ message: '게시물을 찾을 수 없습니다.' });
    }
    res.json(post);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: '게시물을 찾을 수 없습니다.' });
    }

    if (post.author.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: '게시물을 수정할 권한이 없습니다.' });
    }

    post.title = title;
    post.content = content;
    await post.save();
    res.json({ message: '게시물이 성공적으로 수정되었습니다.', post });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: '게시물을 찾을 수 없습니다.' });
    }

    if (post.author.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: '게시물을 삭제할 권한이 없습니다.' });
    }

    await Post.findByIdAndDelete(req.params.id);
    res.json({ message: '게시물이 성공적으로 삭제되었습니다.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 전역 변수로 rooms Map 선언
const rooms = new Map();

io.on('connection', (socket) => {
  console.log('새로운 클라이언트 연결:', socket.id);

  // 방 생성
  socket.on('room:create', ({ roomId, nickname }) => {
    try {
      console.log('방 생성 요청:', { roomId, nickname });
      console.log('현재 존재하는 방 목록:', Array.from(rooms.keys()));

      if (rooms.has(roomId)) {
        socket.emit('room:error', '이미 존재하는 방입니다.');
        return;
      }

      // 새로운 방 생성 및 저장
      const newRoom = {
        id: roomId,
        participants: new Map([[socket.id, nickname]]),
        messages: [],
        createdAt: new Date(),
      };

      rooms.set(roomId, newRoom);
      socket.join(roomId);

      // 방 생성 확인 로그
      console.log(`방 ${roomId} 생성됨. 현재 방 목록:`, Array.from(rooms.keys()));

      socket.emit('room:created', {
        success: true,
        roomId,
        nickname,
        participants: [nickname],
      });
    } catch (error) {
      console.error('방 생성 오류:', error);
      socket.emit('room:error', '이미 존재하거나, 유효하지 않은 방 코드입니다.');
    }
  });

  // 방 확인
  socket.on('room:check', ({ roomId }, callback) => {
    try {
      console.log('방 확인 요청. 방 ID:', roomId);
      console.log('현재 존재하는 방 목록:', Array.from(rooms.keys()));

      const exists = rooms.has(roomId);
      console.log('방 존재 여부:', exists);

      callback({ exists });
    } catch (error) {
      console.error('방 확인 오류:', error);
      callback({ exists: false, error: '방 확인 중 오류가 발생했습니다.' });
    }
  });

  // 방 참여
  socket.on('room:join', async ({ roomId, nickname }) => {
    try {
      console.log('방 참여 요청:', { roomId, nickname });

      const room = rooms.get(roomId);
      if (!room) {
        socket.emit('room:error', '존재하지 않는 방입니다.');
        return;
      }

      // 최대 인원(2명) 체크
      if (room.participants.size >= 2) {
        socket.emit('room:error', '이미 가득 찬 채팅방입니다.');
        return;
      }

      // 이미 참여 중인 사용자인지 확인
      const isAlreadyJoined = Array.from(room.participants.values()).includes(nickname);
      if (isAlreadyJoined) {
        socket.emit('room:error', '이미 참여 중인 닉네임입니다.');
        return;
      }

      // 참가자 추가
      room.participants.set(socket.id, nickname);
      socket.join(roomId);

      // 참여한 사용자에게 성공 메시지 전송
      socket.emit('room:joined', {
        success: true,
        roomId,
        nickname,
        participants: Array.from(room.participants.values()),
      });

      // 모든 참가자에게 새 참가자 알림
      io.to(roomId).emit('room:participant_joined', {
        joinedParticipant: nickname,
        participants: Array.from(room.participants.values()),
      });

      console.log(`${nickname}님이 ${roomId} 방에 참여함`);
      console.log('현재 참가자 목록:', Array.from(room.participants.values()));
    } catch (error) {
      console.error('방 참여 오류:', error);
      socket.emit('room:error', '방 참여 중 오류가 발생했습니다.');
    }
  });

  // room:getParticipants 이벤트 핸들러 추가
  socket.on('room:getParticipants', ({ roomId }) => {
    try {
      const room = rooms.get(roomId);
      if (room) {
        socket.emit('room:participants', {
          participants: Array.from(room.participants.values()),
        });
      }
    } catch (error) {
      console.error('참가자 목록 조회 오류:', error);
    }
  });

  // 방 삭제 이벤트 핸들러 추가
  socket.on('room:delete', ({ roomId, nickname }) => {
    try {
      console.log('방 삭제 요청:', { roomId, nickname });

      const room = rooms.get(roomId);
      if (room) {
        // 모든 참가자에게 방 삭제 알림
        io.to(roomId).emit('room:deleted', {
          message: '방이 삭제되었습니다.',
          deletedBy: nickname,
        });

        // 모든 참가자를 방에서 내보내기
        const participantsInRoom = [...room.participants.values()];
        participantsInRoom.forEach((participant) => {
          socket.to(roomId).emit('room:participant_left', {
            nickname: participant,
            participants: [],
          });
        });

        // 방 삭제
        rooms.delete(roomId);
        console.log(`방 ${roomId} 삭제됨 (사용자에 의해)`);
      }
    } catch (error) {
      console.error('방 삭제 오류:', error);
    }
  });

  // 연결 해제 시
  socket.on('disconnect', () => {
    try {
      console.log('클라이언트 연결 해제:', socket.id);

      // 참여 중이던 방에서 제거
      rooms.forEach((room, roomId) => {
        if (room.participants.has(socket.id)) {
          const nickname = room.participants.get(socket.id);
          room.participants.delete(socket.id);

          if (room.participants.size === 0) {
            console.log(`방 ${roomId} 삭제 (참가자 없음)`);
            rooms.delete(roomId);
          } else {
            socket.to(roomId).emit('room:participant_left', {
              nickname,
              participants: Array.from(room.participants.values()),
            });
          }
        }
      });
    } catch (error) {
      console.error('연결 해제 처리 오류:', error);
    }
  });

  // room:message 이벤트 핸들러 추가
  socket.on('room:message', ({ roomId, message, nickname }) => {
    try {
      console.log('메시지 수신:', { roomId, message, nickname });

      const room = rooms.get(roomId);
      if (!room) {
        socket.emit('room:error', '존재하지 않는 방입니다.');
        return;
      }

      // 메시지 객체 생성
      const messageObj = {
        sender: nickname,
        content: message,
        timestamp: new Date(),
      };

      // 방의 모든 참가자에게 메시지 브로드캐스트
      io.to(roomId).emit('room:message', messageObj);

      // 메시지 저장 (선택사항)
      room.messages = room.messages || [];
      room.messages.push(messageObj);

      console.log(`메시지 전송 완료 - ${nickname}: ${message}`);
    } catch (error) {
      console.error('메시지 전송 오류:', error);
      socket.emit('room:error', '메시지 전송 중 오류가 발생했습니다.');
    }
  });
});

// 서버 시작 시 rooms 초기화 로그
console.log('서버 시작. rooms Map 초기화됨');

// 주기적으로 오래된 방 정리 (옵션)
setInterval(() => {
  const now = new Date();
  rooms.forEach((room, roomId) => {
    // 24시간 이상 된 방이고 참가자가 없는 경우 삭제
    if (now - room.createdAt > 24 * 60 * 60 * 1000 && room.participants.size === 0) {
      rooms.delete(roomId);
      console.log(`오래된 방 ${roomId} 삭제됨`);
    }
  });
}, 60 * 60 * 1000); // 1시간마다 체크

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

server.listen(port, () => {
  console.log(`서버가 포트 ${port}에서 실행 중입니다.`);
});
