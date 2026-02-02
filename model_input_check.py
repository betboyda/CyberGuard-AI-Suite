from tensorflow.keras.models import load_model

model = load_model("model/face_model.h5")
print("Giriş boyutu:", model.input_shape)
model.summary()

