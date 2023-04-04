# need to run inside tf1 virtual env (conda activate tf1)
# todo: if possible, activate tf1
# todo: if no dir /home/amit.zr/infoSecurityProj/bin2name/server_side/binary2name/our_dataset/nero_ds/ add it
# todo: if no dir /home/amit.zr/infoSecurityProj/bin2name/server_side/binary2name/nero_dataset_binaries/TEST add it
# todo: if no dir /home/amit.zr/infoSecurityProj/bin2name/server_side/binary2name/nero_dataset_binaries/TRAIN add it
# todo: if no dir /home/amit.zr/infoSecurityProj/bin2name/server_side/binary2name/nero_dataset_binaries/VALIDATE add it

echo "Welcome! We are Amit and Snir."
 echo "You are running prediction"
echo "Remember - If you're running on Lambda, usr srun!"
echo "Also remember to have all your modules installed - angr and TensorFlow 1 included."


date +%H:%M:%S
echo "Running symbolic analysis"
python3 run_pproc.py --output_dir nero --dataset_dir nero_ds --log_dir nero_logs --cpu_no 30 --mem_limit 10 --no_usables_file --predict

date +%H:%M:%S
echo "Running output processing and conversion"
yes | python3 output_converter.py --train 0 --test 100 --val 0 --dataset_name nero --sample_path 1 --sample_constraint 3 --predict

date +%H:%M:%S
echo "Removing empty lines (feel free to find a better way)"
grep . ready_data/ready_nero/train.json > ready_data/ready_nero/train.json_
mv ready_data/ready_nero/train.json_ ready_data/ready_nero/train.json
grep . ready_data/ready_nero/validation.json > ready_data/ready_nero/validation.json_
mv ready_data/ready_nero/validation.json_ ready_data/ready_nero/validation.json
grep . ready_data/ready_nero/test.json > ready_data/ready_nero/test.json_
mv ready_data/ready_nero/test.json_ ready_data/ready_nero/test.json


date +%H:%M:%S
echo "Copying to nero's internal data directory"
mkdir -p nero/nero/procedure_representations/raw/bin2name
cp ready_data/ready_nero/train.json nero/nero/procedure_representations/raw/bin2name/train.json
cp ready_data/ready_nero/validation.json nero/nero/procedure_representations/raw/bin2name/validation.json
cp ready_data/ready_nero/test.json nero/nero/procedure_representations/raw/bin2name/test.json

date +%H:%M:%S
echo "Running Nero's preprocessing"
cd nero/nero
python3 ../preprocess.py -trd procedure_representations/raw/bin2name/train.json -ted procedure_representations/raw/bin2name/test.json -vd procedure_representations/raw/bin2name/validation.json -o data --predict

date +%H:%M:%S
echo "Copying to nero's internal preprocessed directory"
mkdir -p procedure_representations/preprocessed/bin2name
mv data.dict procedure_representations/preprocessed/bin2name
mv data.train procedure_representations/preprocessed/bin2name
mv data.val procedure_representations/preprocessed/bin2name
mv data.test procedure_representations/preprocessed/bin2name

cd ..
date +%H:%M:%S
echo "Running Nero"
python3 -u gnn.py --test nero/procedure_representations/preprocessed/bin2name/data.test --load nero/new_model/model_iter_last --gnn_layers 4

date +%H:%M:%S
echo "That's All, Folks!"
