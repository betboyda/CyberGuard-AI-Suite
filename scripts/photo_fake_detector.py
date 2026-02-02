import os
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import img_to_array, load_img

def predict_photo_deepfake(photo_path, model_path):
    """
    Fotoğrafı model ile analiz edip 'Gerçek' veya 'Sahte' sonucunu ve olasılığı döner.

    Args:
        photo_path (str): Fotoğraf dosya yolu.
        model_path (str): Yüz DeepFake modelinin dosya yolu (ör. face_model.h5).

    Returns:
        tuple: ('Gerçek' veya 'Sahte', olasılık [0.0 - 1.0])
    """
    model = load_model(model_path)
    image = load_img(photo_path, target_size=(64, 64))
    image = img_to_array(image)
    image = image.astype("float") / 255.0
    image = np.expand_dims(image, axis=0)

    pred = model.predict(image)[0][0]

    label = "Sahte" if pred > 0.5 else "Gerçek"
    return label, pred  # hem sınıf etiketi hem de güven puanı
