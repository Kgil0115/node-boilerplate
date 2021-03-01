const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50,
  },
  email: {
    type: String,
    trim: true,
    unique: 1,
  },
  password: {
    type: String,
    minlength: 5,
  },
  role: {
    type: Number, // 1 이면 관리자, 0이면 일반유저
    default: 0,
  },
  image: String,
  token: {
    type: String,
  },
  tokenExp: {
    type: Number,
  },
});

userSchema.pre('save', function(next) {
  var user = this;

  if (user.isModified('password')) {
    // 비밀번호를 암호화 시킨다.
    bcrypt.genSalt(saltRounds, function(err, salt) {
      if (err) return next(err);
      bcrypt.hash(user.password, salt, function(err, hash) {
        if (err) return next(err);
        user.password = hash;
        next();
      });
    });
  } else {
    next();
  }
});

userSchema.methods.comparePassword = function(plainPassword, cb) {
  //plainPassword 1234567     암호화된 비밀번호 $2b$10$77w8acqKq/KzBTDVId1ZSush0D93/Z7BDCFVHv3GsYAMOwXSYZeBy
  // 암호화된 비밀번호를 복호화 할 수는 없으므로 플레인 비번을 암호화시켜서 비교해야함
  bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch); // isMatch는 true
  });
};

userSchema.methods.generateToken = function(cb) {
  var user = this;
  //jwt이용해서 token 생성
  var token = jwt.sign(user._id.toHexString(), 'secretToken');

  //user._id + 'secretToken' = token
  user.token = token;
  user.save(function(err, user) {
    if (err) return cb(err);
    cb(null, user);
  });
};

userSchema.statics.findByToken = function(token, cb) {
  var user = this;
  //토큰을 디코드 한다.
  jwt.verify(token, 'secretToken', function(err, decoded) {
    //유저 아이디를 이용해서 유저를 찾은 다음에
    // 클라이언트에서 가져온 토큰과 DB에 보관된 토큰이 일치하는지 확인
    user.findOne({ _id: decoded, token: token }, function(err, user) {
      if (err) return cb(err);
      cb(null, user);
    });
  });
};

const User = mongoose.model('User', userSchema);

module.exports = { User };
