#!/bin/bash
set -e

file_env() {
	var="$1"
	fileVar="${var}_FILE"
	def="nada"
	if [[ -f "${fileVar}" ]]; then
	  val="$(cat "${fileVar}")"
	elif [[ -z ${var} ]]; then
	  val="${var}"
	else
		val="$def"
	fi
	export "$var"="$val"
	unset "$fileVar"
}

if [[ -n $SECRET_KEY || -n $SECRET_KEY_FILE ]]; then
  file_env 'SECRET_KEY'
fi

# check to see if (DB_ACCESS_URI is given) or else (RDS_PSWD and RDS_INST) or else (fail)
if [[ -n $UTOPIA_DB_URI || -n $UTOPIA_DB_URI ]]; then
  file_env 'DB_ACCESS_URI'
elif [[ -n $RDS_PSWD && -n $RDS_INST ]]; then
  file_env 'RDS_PSWD'
  file_env 'RDS_INST'
elif [[ -n $RDS_PSWD_FILE && -n $RDS_INST_FILE ]]; then
  file_env 'RDS_PSWD'
  file_env 'RDS_INST'
else
  echo "Neither the database access uri (DB_ACCESS_URI) nor the RDS password and instance variables"
  echo "(RDS_PSWD and RDS_INST) have been set, please insert either one or the other in your build"
  echo "with --build-arg VARIABLE='value' or VARIABLE_FILE=/path/to/file'"
fi

source /home/utopian/venv/bin/activate
# flask db upgrade

exec flask run
