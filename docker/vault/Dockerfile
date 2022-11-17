FROM python:3.7.15-bullseye

RUN apt update \
    && apt install --yes build-essential flex bison wget subversion m4 python3 python3-dev python3-setuptools libgmp-dev libssl-dev gcc git

#Install PBC from source
RUN wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && tar xf pbc-0.5.14.tar.gz \
    && cd pbc-0.5.14 \
    && ./configure LDFLAGS="-lgmp" \
    && make \
    && make install \
    && ldconfig

#Next, we will install Charm. Navigate to your Charm directory.
#We must first run the configuration script:

RUN git clone https://github.com/JHUISI/charm.git \
    && cd charm \
    && ./configure.sh \
    && make \
    && make install \
    && ldconfig

RUN pip install "poetry==1.2"
WORKDIR /code
COPY poetry.lock pyproject.toml /code/

# Project initialization:
RUN poetry config virtualenvs.create false \
    && poetry install --without charm --no-interaction --no-ansi --no-root

COPY /src/vault /code    

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]    

