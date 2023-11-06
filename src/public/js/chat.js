const socketClient = io();

const formMsj = document.getElementById("msjForm");
const formMail = document.getElementById("email");
const formChat = document.getElementById("chat");
const formText = document.getElementById("msj");


formMsj.onsubmit = (e) => {
  e.preventDefault();
  const infoMessage = {
    email: formMail.value,
    message: formText.value,
  };
  socketClient.emit("message", infoMessage);
};

socketClient.on("chat", (messages) => {
  const chat = messages
    .map((objMessage) => `<p>${objMessage.email}: ${objMessage.message}</p>`)
    .join(" ");
  formChat.innerHTML = chat;
});
