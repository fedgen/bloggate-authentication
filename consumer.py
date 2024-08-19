# amqps://qjxiphqt:mA9DB_ZIzT-0z09Q0kvnafJ6M6Mox26G@rattlesnake.rmq.cloudamqp.com/qjxiphqt

import pika

params = pika.URLParameters('amqps://qjxiphqt:mA9DB_ZIzT-0z09Q0kvnafJ6M6Mox26G@rattlesnake.rmq.cloudamqp.com/qjxiphqt')

connection = pika.BlockingConnection(params)

channel = connection.channel()

channel.queue_declare(queue='admin')

def callback(ch, method, properties, body):
    pass

channel.basic_consume(queue='admin', on_message_callback=callback, auto_ack=True)
print('started Consuming')
channel.start_consuming()
channel.close()