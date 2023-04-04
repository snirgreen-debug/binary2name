from csv import reader, writer
from difflib import SequenceMatcher

RESULTS_FILE_PATH = 'results.csv'
SIMILAR_THRESH = 0.85


def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()


def is_garbage(real_name, chat_gpt_answer):
    garbage_key_words = ["prologue", "epilogue", "entry", "setup"]
    for word in garbage_key_words:
        if word in chat_gpt_answer.lower() and word not in real_name.lower():
            return True
    return False


def has_common_word(real_name, chat_gpt_answer):
    real_name_delimiter = '_'
    for word in real_name.split(real_name_delimiter):
        if word.lower() in chat_gpt_answer.lower().split(' '):
            return True
    return False


def write_data(csv_file, data):
    with open(csv_file, 'a') as file:
        csv_writer = writer(file)
        for line in data:
            csv_writer.writerow(line)


def main():
    same = []
    garbage = []
    common_word = []
    all_the_rest = []

    with open(RESULTS_FILE_PATH, 'r') as res_file:
        csv_reader = reader(res_file)
        for line in csv_reader:
            if not line:
                continue
            _, real_name, _, chat_gpt_answer = line

            # garbage collector
            if is_garbage(real_name, chat_gpt_answer):
                garbage.append(line)

            # common word collector
            elif has_common_word(real_name, chat_gpt_answer):
                common_word.append(line)

            # same collector
            elif similar(real_name, chat_gpt_answer) > SIMILAR_THRESH:
                same.append(line)

            else:
                all_the_rest.append(line)

    write_data('results_same.csv', same)
    write_data('results_garbage.csv', garbage)
    write_data('results_common_word.csv', common_word)
    write_data('results_all_the_rest.csv', all_the_rest)


if __name__ == '__main__':
    main()
