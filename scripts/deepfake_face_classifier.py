import os
import numpy as np
import cv2
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Dropout
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

REAL_PATH = "data/faces/real"
FAKE_PATH = "data/faces/fake"
IMG_SIZE = 64

def load_images(folder, label):
    images = []
    labels = []
    for filename in os.listdir(folder):
        path = os.path.join(folder, filename)
        img = cv2.imread(path)
        if img is not None:
            img = cv2.resize(img, (IMG_SIZE, IMG_SIZE))
            images.append(img)
            labels.append(label)
    return images, labels

print("[1] Görseller yükleniyor...")
real_images, real_labels = load_images(REAL_PATH, 0)
fake_images, fake_labels = load_images(FAKE_PATH, 1)

X = np.array(real_images + fake_images)
y = np.array(real_labels + fake_labels)

X = X / 255.0
y = to_categorical(y, 2)

print("[2] Veri eğitim/test için ayrılıyor...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("[3] CNN modeli tanımlanıyor...")
model = Sequential([
    Conv2D(32, (3, 3), activation='relu', input_shape=(IMG_SIZE, IMG_SIZE, 3)),
    MaxPooling2D((2, 2)),
    Conv2D(64, (3, 3), activation='relu'),
    MaxPooling2D((2, 2)),
    Flatten(),
    Dense(128, activation='relu'),
    Dropout(0.3),
    Dense(2, activation='softmax')
])

model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

print("[4] Model eğitiliyor...")
callbacks = [
    EarlyStopping(patience=5, restore_best_weights=True),
    ModelCheckpoint("model/face_classifier.h5", save_best_only=True)
]

history = model.fit(X_train, y_train, epochs=20, batch_size=32, validation_split=0.2, callbacks=callbacks)

print("[✅] Eğitim tamamlandı. Model kaydedildi: model/face_classifier.h5")
