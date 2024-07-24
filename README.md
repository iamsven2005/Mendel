# Python Hello World

This example shows how to use Python on Vercel with Serverless Functions using the [Python Runtime](https://vercel.com/docs/concepts/functions/serverless-functions/runtimes/python).

## Demo

https://python-hello-world.vercel.app/

## Running Locally

```bash
npm install
cd api
python index.py
```

Your Python API is now available at `http://localhost:3000/api`.

## One-Click Deploy

Deploy the example using [Vercel](https://vercel.com?utm_source=github&utm_medium=readme&utm_campaign=vercel-examples):

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fnyp-tech%2Fnyp-tech%2Ftree%2Fmain%2Fflask-npx&demo-title=Flask%20Hello%20World&demo-description=Use%20Python%20on%20Vercel%20with%20Serverless%20Functions%20using%20the%20Python%20Runtime.&demo-url=https%3A%2F%2Fpython-hello-world.vercel.app%2F&demo-image=https://assets.vercel.com/image/upload/v1669994600/random/python.png)


python -m venv env
env\Scripts\activate
 pip install -r requirements.txt
 cd api
 flask run
