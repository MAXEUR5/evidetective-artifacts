from Utils.WebUtil import *
from Utils.Logger import slog

class AgentEntity:
    def __init__(self, name:str, interactive:bool=False):
        self.name            = name
        self.interactive     = interactive
        self.context_history = []

    # ========== First round: specify system + user ==========
    def create(self, sys_message:str, user_message:str):
        sys_msg  = MsgEntity("system", sys_message)
        user_msg = MsgEntity("user",   user_message)
        self.context_history = [sys_msg, user_msg]

        slog.white(sys_msg.message)
        slog.white(user_msg.message)

        ans = gpt_send_chat(self.context_history)
        self.context_history.append(ans)
        return ans

    # ========== Subsequent dialogue ==========
    def send(self, user_message:str):
        """Append a user message and fetch the assistant reply."""
        usr = MsgEntity("user", user_message)
        self.context_history.append(usr)
        slog.white(usr.message)

        ans = gpt_send_chat(self.context_history)
        self.context_history.append(ans)
        return ans