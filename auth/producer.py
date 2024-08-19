# amqps://qjxiphqt:mA9DB_ZIzT-0z09Q0kvnafJ6M6Mox26G@rattlesnake.rmq.cloudamqp.com/qjxiphqt
'''
import pika, json

params = pika.URLParameters('amqps://qjxiphqt:mA9DB_ZIzT-0z09Q0kvnafJ6M6Mox26G@rattlesnake.rmq.cloudamqp.com/qjxiphqt')
connection = pika.BlockingConnection(params)


channel = connection.channel()

def publishUser(method, body):
    properties = pika.BasicProperties(method)
    channel.basic_publish(exchange='', routing_key='4DpeU\.W6fe=pJbQ', body=json.dumps(body), properties=properties)
'''