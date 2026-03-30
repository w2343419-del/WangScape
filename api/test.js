module.exports = (req, res) => {
  res.json({ message: "Hello from WangScape API", timestamp: Date.now() });
};
