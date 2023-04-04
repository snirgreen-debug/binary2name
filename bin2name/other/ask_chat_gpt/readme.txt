asking from chatGPT for each function about fitting name.
save in results.csv:
func_addr, func_real_name, func_predicted_name(predicted by nero), chatGPT_answer.


then, we can classify to different categories with classify_results.py by matches of real_name and chatGPT answer:
- "garbage" (e.g. "function prolouge").
- same name (i.e. the real name and the chatGPT answer were the same).
- common word (between real name and the chatGPT answer).
- none of the above.