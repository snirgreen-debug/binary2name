#!/bin/bash

echo "Welcome! This is an execution bash script for the nero results, using only 65% of the data (assuming symbolic execution is already done)"
echo "Remember - If you're running on Lambda, usr srun!"
echo "First run 'srun -c 'number of cpus you would like to use' --gres=gpu:'number of gpus you would like to use' --pty \bin\bash' to get a hold of one of the lambda nodes"
echo "Also remember to have all your modules installed - angr and TensorFlow 1 included."

echo "Running output processing and conversion"
yes | python3 output_converter.py --dataset_name nero

echo "Removing empty lines (feel free to find a better way)"
grep . ready_data/ready_nero/train.json > ready_data/ready_nero/train.json_
mv ready_data/ready_nero/train.json_ ready_data/ready_nero/train.json
grep . ready_data/ready_nero/validation.json > ready_data/ready_nero/validation.json_
mv ready_data/ready_nero/validation.json_ ready_data/ready_nero/validation.json
grep . ready_data/ready_nero/test.json > ready_data/ready_nero/test.json_
mv ready_data/ready_nero/test.json_ ready_data/ready_nero/test.json

echo "Copying to nero's internal data directory"
mkdir -p nero/nero/procedure_representations/raw/bin2name
cp ready_data/ready_nero/train.json nero/nero/procedure_representations/raw/bin2name/train.json
cp ready_data/ready_nero/validation.json nero/nero/procedure_representations/raw/bin2name/validation.json
cp ready_data/ready_nero/test.json nero/nero/procedure_representations/raw/bin2name/test.json

echo "Running Nero's preprocessing"
cd nero/nero
python3 ../preprocess.py -trd procedure_representations/raw/bin2name/train.json -ted procedure_representations/raw/bin2name/test.json -vd procedure_representations/raw/bin2name/validation.json -o data

echo "Copying to nero's internal preprocessed directory"
mkdir -p procedure_representations/preprocessed/bin2name
mv data.dict procedure_representations/preprocessed/bin2name
mv data.train procedure_representations/preprocessed/bin2name
mv data.val procedure_representations/preprocessed/bin2name
mv data.test procedure_representations/preprocessed/bin2name

echo "Running Nero"
python3 -u ../gnn.py  --data procedure_representations/preprocessed/bin2name/data --test procedure_representations/preprocessed/bin2name/data.test --save new_model/model --gnn_layers 4 > nero_out_log.txt 2> nero_error_log.txt

echo "That's All, Folks!"
